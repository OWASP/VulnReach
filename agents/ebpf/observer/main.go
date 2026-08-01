// VulnReach eBPF observer (P0 skeleton).
//
// Loads the CO-RE object, attaches the sched_process_exec tracepoint,
// optionally filters to a set of target cgroup ids, and streams events as
// NDJSON (one JSON object per line) on stdout. Control lines: ready / error /
// summary. See docs/ebpf-p0-spec.md §5 for the wire schema.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type event observer observer.bpf.c -- -I.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
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

func main() {
	var cgids cgidFlags
	flag.Var(&cgids, "cgroup-id", "target cgroup id (repeatable); none => observe all")
	duration := flag.Int("duration", 0, "seconds to run (0 = until SIGINT/SIGTERM)")
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

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fatal("ringbuf reader: " + err.Error())
	}
	defer rd.Close()

	emit(map[string]any{"v": 1, "type": "ready", "cgroup_ids": []uint64(cgids),
		"progs": []string{"sched_process_exec", "sys_enter_openat", "sys_enter_openat2", "sys_enter_mmap"}})

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
