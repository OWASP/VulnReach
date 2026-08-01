// VulnReach eBPF observer (P0 skeleton).
//
// Loads the CO-RE object, attaches the sched_process_exec tracepoint,
// optionally filters to a set of target cgroup ids, and streams events as
// NDJSON (one JSON object per line) on stdout. Control lines: ready / error /
// summary. See docs/ebpf-p0-spec.md §5 for the wire schema.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type event observer observer.bpf.c -- -I. -D__TARGET_ARCH_$GOARCH

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type cgidFlags []uint64

func (c *cgidFlags) String() string { return fmt.Sprint(*c) }
func (c *cgidFlags) Set(v string) error {
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return err
	}
	*c = append(*c, n)
	return nil
}

func emit(v map[string]any) {
	b, _ := json.Marshal(v)
	os.Stdout.Write(append(b, '\n'))
}

func fatal(msg string) {
	emit(map[string]any{"v": 1, "type": "error", "msg": msg})
	os.Exit(1)
}

// cstr converts a NUL-terminated int8 array (C char[]) to a Go string.
func cstr(b []int8) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

// pyOffsets are the CPython struct offsets the Tier B uprobe needs. Every value
// was derived empirically from stock python:<v>-slim images (ctypes for the
// Python-visible structs, internal/pycore_frame.h for _PyInterpreterFrame) —
// not from memory of the CPython sources.
//
//	frameArg  1 => _PyEval_EvalFrameDefault(PyFrameObject*, int)          (<=3.8)
//	          2 => _PyEval_EvalFrameDefault(PyThreadState*, frame*, int)  (3.9+)
//	codeOff   f_code within PyFrameObject (<=3.10) / _PyInterpreterFrame (3.11+)
//	fnameOff  co_filename within PyCodeObject
//	payload   char data within the str object; PyASCIIObject lost its `wstr`
//	          member in 3.12, shrinking the header from 48 to 40
type pyOffsets struct{ frameArg, codeOff, fnameOff, payload uint32 }

var pyOffsetTable = map[string]pyOffsets{
	"3.8":  {1, 32, 104, 48},
	"3.9":  {2, 32, 104, 48},
	"3.10": {2, 32, 104, 48},
	"3.11": {2, 32, 112, 48},
	"3.12": {2, 0, 112, 40},
	"3.13": {2, 0, 112, 40},
}

var pyVersionRe = regexp.MustCompile(`python(\d+)\.(\d+)`)

// pyVersionFromPath pulls "3.11" out of e.g.
// /proc/42/root/usr/local/lib/libpython3.11.so.1.0
func pyVersionFromPath(p string) string {
	m := pyVersionRe.FindStringSubmatch(p)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2]
}

// attachPython wires up Tier B. Every failure path is a warn, never a fatal:
// the Tier A baseline must stand on its own if enrichment is unavailable
// (redesign D-note: "baseline reachability must never depend on it").
// Returns the closer and whether the probe attached.
func attachPython(objs *observerObjects, libPath, version string) (link.Link, bool) {
	if libPath == "" {
		return nil, false
	}
	if version == "" {
		version = pyVersionFromPath(libPath)
	}
	off, ok := pyOffsetTable[version]
	if !ok {
		emit(map[string]any{"v": 1, "type": "warn",
			"msg": "tier-b: unsupported python version " + strconv.Quote(version) + " for " + libPath})
		return nil, false
	}

	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		emit(map[string]any{"v": 1, "type": "warn", "msg": "tier-b: open " + libPath + ": " + err.Error()})
		return nil, false
	}
	// _PyEval_EvalFrameDefault is the modern eval loop; PyEval_EvalFrameEx is
	// the older exported wrapper. Both live in .dynsym, so no debug symbols or
	// USDT (--with-dtrace) build is required.
	var lk link.Link
	var lastErr error
	for _, sym := range []string{"_PyEval_EvalFrameDefault", "PyEval_EvalFrameEx"} {
		if lk, lastErr = ex.Uprobe(sym, objs.HandlePyFrame, nil); lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		emit(map[string]any{"v": 1, "type": "warn", "msg": "tier-b: uprobe attach: " + lastErr.Error()})
		return nil, false
	}

	// Publish offsets only once the probe is live, so a half-configured map can
	// never make the program read garbage.
	for k, v := range map[uint32]uint32{0: off.frameArg, 1: off.codeOff, 2: off.fnameOff, 3: off.payload} {
		if err := objs.PyCfg.Put(k, v); err != nil {
			emit(map[string]any{"v": 1, "type": "warn", "msg": "tier-b: py_cfg.Put: " + err.Error()})
			lk.Close()
			return nil, false
		}
	}
	return lk, true
}

func main() {
	var cgids cgidFlags
	flag.Var(&cgids, "cgroup-id", "target cgroup id (repeatable); none => observe all")
	duration := flag.Int("duration", 0, "seconds to run (0 = until SIGINT/SIGTERM)")
	pythonLib := flag.String("python-lib", "", "host-visible path to the target's libpython (Tier B enrichment; best-effort)")
	pythonVersion := flag.String("python-version", "", "target CPython version e.g. 3.11 (default: inferred from --python-lib)")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		fatal("removememlock: " + err.Error())
	}

	objs := observerObjects{}
	if err := loadObserverObjects(&objs, nil); err != nil {
		fatal("load objects: " + err.Error())
	}
	defer objs.Close()

	if len(cgids) > 0 {
		var one uint8 = 1
		for _, id := range cgids {
			if err := objs.Targets.Put(id, one); err != nil {
				fatal("targets.Put: " + err.Error())
			}
		}
		var k, v uint32 = 0, 1
		if err := objs.FilterOn.Put(k, v); err != nil {
			fatal("filter_on.Put: " + err.Error())
		}
	}

	// Required tracepoints. openat2 is best-effort (absent on older kernels).
	required := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"sched", "sched_process_exec", objs.HandleExec},
		{"syscalls", "sys_enter_openat", objs.HandleOpenat},
		{"syscalls", "sys_enter_mmap", objs.HandleMmap},
	}
	for _, t := range required {
		lk, err := link.Tracepoint(t.group, t.name, t.prog, nil)
		if err != nil {
			fatal("attach " + t.group + ":" + t.name + ": " + err.Error())
		}
		defer lk.Close()
	}
	if lk, err := link.Tracepoint("syscalls", "sys_enter_openat2", objs.HandleOpenat2, nil); err != nil {
		emit(map[string]any{"v": 1, "type": "warn", "msg": "openat2 unavailable: " + err.Error()})
	} else {
		defer lk.Close()
	}

	progs := []string{"sched_process_exec", "sys_enter_openat", "sys_enter_openat2", "sys_enter_mmap"}
	if lk, ok := attachPython(&objs, *pythonLib, *pythonVersion); ok {
		defer lk.Close()
		progs = append(progs, "uprobe:py_eval_frame")
		// Control channel: a "mark" line on stdin bumps the Tier B dedupe epoch.
		// Almost every package executes during import, so without this the
		// per-file dedupe would permanently mask the request-handling frames we
		// actually care about. Bumping at the boot->traffic boundary re-opens
		// every file for one more report.
		go func() {
			sc := bufio.NewScanner(os.Stdin)
			var epoch uint32
			for sc.Scan() {
				if strings.TrimSpace(sc.Text()) != "mark" {
					continue
				}
				epoch++
				if err := objs.PyCfg.Put(uint32(4), epoch); err != nil {
					emit(map[string]any{"v": 1, "type": "warn", "msg": "mark: " + err.Error()})
					continue
				}
				emit(map[string]any{"v": 1, "type": "marked", "epoch": epoch})
			}
		}()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fatal("ringbuf reader: " + err.Error())
	}
	defer rd.Close()

	emit(map[string]any{"v": 1, "type": "ready", "cgroup_ids": []uint64(cgids), "progs": progs})

	// Close the reader on signal or after --duration; that unblocks rd.Read().
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if *duration > 0 {
			select {
			case <-sig:
			case <-time.After(time.Duration(*duration) * time.Second):
			}
		} else {
			<-sig
		}
		rd.Close()
	}()

	var count uint64
	start := time.Now()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}
		var e observerEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		count++
		typ := "exec"
		switch e.Kind {
		case 1:
			typ = "open"
		case 2:
			typ = "mmap_exec"
		case 3:
			typ = "py_call"
		}
		emit(map[string]any{
			"v":         1,
			"type":      typ,
			"ts_ns":     e.TsNs,
			"cgroup_id": e.CgroupId,
			"pid":       e.Pid,
			"ppid":      e.Ppid,
			"comm":      cstr(e.Comm[:]),
			"filename":  cstr(e.Filename[:]),
		})
	}

	emit(map[string]any{"v": 1, "type": "summary", "events": count, "duration_ms": time.Since(start).Milliseconds()})
}
