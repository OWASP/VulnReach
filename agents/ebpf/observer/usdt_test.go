package main

import "testing"

// The USDT argument descriptor is the one piece of the observer whose behaviour
// is genuinely architecture-conditional in *userspace*, and until CI ran on
// amd64 the whole project had only ever executed the arm64 branch. These tests
// need no kernel, no privileges and no BPF, so they run on every arch on every
// push — which is exactly why the amd64 mapping belongs here rather than in the
// privileged suite.
//
// The descriptor under test is the real one from a stock JDK's libjvm.so:
//
//	hotspot:class__loaded  ->  "8@x3 -4@x2 8@[x0,152] 1@x1"
//
// Note it is NOT in calling-convention order: the class name is in the 4th
// parameter register, the length in the 3rd, and one operand is a memory
// reference that cannot be read from a register at all.
const jdkClassLoadedArgs = "8@x3 -4@x2 8@[x0,152] 1@x1"

func TestArgRegArm64(t *testing.T) {
	p := usdtProbe{Args: jdkClassLoadedArgs}
	cases := []struct{ n, want int }{
		{0, 4}, // x3 -> parm4  (class name)
		{1, 3}, // x2 -> parm3  (name length)
		{2, 0}, // 8@[x0,152] is a memory operand -> unreadable
		{3, 2}, // x1 -> parm2
	}
	for _, c := range cases {
		if got := p.ArgReg(c.n, "arm64"); got != c.want {
			t.Errorf("ArgReg(%d, arm64) = %d, want %d", c.n, got, c.want)
		}
	}
}

func TestArgRegAmd64(t *testing.T) {
	// Same probe as an x86-64 build spells it: the System V argument registers.
	p := usdtProbe{Args: "8@%rcx -4@%rdx 8@[%rdi,152] 1@%rsi"}
	cases := []struct{ n, want int }{
		{0, 4}, // rcx -> parm4
		{1, 3}, // rdx -> parm3
		{2, 0}, // memory operand
		{3, 2}, // rsi -> parm2
	}
	for _, c := range cases {
		if got := p.ArgReg(c.n, "amd64"); got != c.want {
			t.Errorf("ArgReg(%d, amd64) = %d, want %d", c.n, got, c.want)
		}
	}
}

func TestArgRegRejectsForeignArchRegisters(t *testing.T) {
	// An arm64 descriptor read on amd64 (or vice versa) must yield 0 rather than
	// a plausible-looking index: a wrong register silently reads an unrelated
	// value and would attribute a garbage class name to a real package.
	p := usdtProbe{Args: jdkClassLoadedArgs}
	for n := 0; n < 4; n++ {
		if got := p.ArgReg(n, "amd64"); got != 0 {
			t.Errorf("ArgReg(%d, amd64) on an arm64 descriptor = %d, want 0", n, got)
		}
	}
	if got := p.ArgReg(0, "riscv64"); got != 0 {
		t.Errorf("unknown arch should yield 0, got %d", got)
	}
}

func TestArgRegOutOfRange(t *testing.T) {
	p := usdtProbe{Args: "8@x0"}
	if got := p.ArgReg(5, "arm64"); got != 0 {
		t.Errorf("ArgReg past the end = %d, want 0", got)
	}
	empty := usdtProbe{}
	if got := empty.ArgReg(0, "arm64"); got != 0 {
		t.Errorf("ArgReg on an empty descriptor = %d, want 0", got)
	}
}

func TestArgRegAcceptsOptionalPercentAndSign(t *testing.T) {
	// Descriptors vary: sizes may be negative (signed) and registers may or may
	// not carry a leading '%' depending on the toolchain that emitted them.
	for _, args := range []string{"8@x1", "8@%x1", "-8@x1", "-4@%x1"} {
		p := usdtProbe{Args: args}
		if got := p.ArgReg(0, "arm64"); got != 2 {
			t.Errorf("ArgReg(0, arm64) for %q = %d, want 2", args, got)
		}
	}
}
