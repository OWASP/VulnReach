// Minimal USDT (SystemTap probe) support.
//
// cilium/ebpf has no USDT helper, so we parse `.note.stapsdt` ourselves. Each
// note records where the probe's nop sits and how to find its arguments:
//
//	Provider: hotspot
//	Name: class__loaded
//	Location: 0x58dcbc, Base: 0x1033008, Semaphore: 0x0
//	Arguments: 8@x3 -4@x2 8@[x0, 152] 1@x1
//
// We need two things from that: a file offset to attach a uprobe at, and which
// register each argument lives in. Arguments are NOT in calling-convention
// order — for hotspot:class__loaded the name is in x3 (the 4th parameter
// register) — which is why the register has to be resolved here and handed to
// the BPF program rather than compiled in.
package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

type usdtProbe struct {
	Provider string
	Name     string
	Location uint64
	Base     uint64
	Args     string
}

// argRegs maps an argument descriptor to parameter-register indices (1-based).
// Only plain-register operands are supported; memory operands like "8@[x0,152]"
// return 0, which callers treat as "cannot read this argument".
var paramRegs = map[string][]string{
	"arm64": {"x0", "x1", "x2", "x3", "x4", "x5"},
	"amd64": {"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
}

var usdtArgRe = regexp.MustCompile(`^-?\d+@%?([a-z0-9]+)$`)

// ArgReg returns the 1-based parameter index for argument n, or 0 if that
// argument is not in a parameter register on this architecture.
func (p usdtProbe) ArgReg(n int, arch string) int {
	fields := strings.Fields(p.Args)
	if n >= len(fields) {
		return 0
	}
	m := usdtArgRe.FindStringSubmatch(fields[n])
	if m == nil {
		return 0 // memory operand or immediate
	}
	for i, r := range paramRegs[arch] {
		if r == m[1] {
			return i + 1
		}
	}
	return 0
}

// findUSDT locates a probe by provider and name.
func findUSDT(path, provider, name string) (usdtProbe, error) {
	f, err := elf.Open(path)
	if err != nil {
		return usdtProbe{}, err
	}
	defer f.Close()

	sec := f.Section(".note.stapsdt")
	if sec == nil {
		return usdtProbe{}, fmt.Errorf("%s: no .note.stapsdt section", path)
	}
	data, err := sec.Data()
	if err != nil {
		return usdtProbe{}, err
	}

	for off := 0; off+12 <= len(data); {
		namesz := binary.LittleEndian.Uint32(data[off:])
		descsz := binary.LittleEndian.Uint32(data[off+4:])
		off += 12 + align4(int(namesz))
		if off+int(descsz) > len(data) {
			break
		}
		desc := data[off : off+int(descsz)]
		off += align4(int(descsz))
		if len(desc) < 24 {
			continue
		}
		p := usdtProbe{
			Location: binary.LittleEndian.Uint64(desc[0:]),
			Base:     binary.LittleEndian.Uint64(desc[8:]),
		}
		// provider\0 name\0 args\0
		parts := bytes.SplitN(desc[24:], []byte{0}, 4)
		if len(parts) < 3 {
			continue
		}
		p.Provider, p.Name, p.Args = string(parts[0]), string(parts[1]), string(parts[2])
		if p.Provider == provider && p.Name == name {
			return p, nil
		}
	}
	return usdtProbe{}, fmt.Errorf("%s: probe %s:%s not found", path, provider, name)
}

func align4(n int) int { return (n + 3) &^ 3 }

// fileOffset converts the probe's recorded virtual address into an offset into
// the file, which is what a uprobe attaches to.
//
// Two corrections are needed. First, if the ELF was prelinked its addresses
// shifted, which the `.stapsdt.base` section lets us undo (this is the standard
// libbpf/bcc fixup). Second, a virtual address is not a file offset, so we map
// it back through whichever PT_LOAD segment contains it.
func (p usdtProbe) fileOffset(path string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	loc := p.Location
	if base := f.Section(".stapsdt.base"); base != nil && p.Base != 0 {
		loc += base.Addr - p.Base
	}
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && loc >= prog.Vaddr && loc < prog.Vaddr+prog.Memsz {
			return loc - prog.Vaddr + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("%s: address %#x not in any PT_LOAD segment", path, loc)
}
