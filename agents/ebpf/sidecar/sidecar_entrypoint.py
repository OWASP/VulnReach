#!/usr/bin/env python3
"""VulnReach eBPF sidecar — standalone bpftrace coverage collector.

Runs inside a privileged container that shares the target service's PID
namespace (``pid: "service:<target>"``).  Attaches bpftrace probes to the
target process, waits for Schemathesis traffic driven by the VulnReach agent,
then writes NormalisedCoverage JSON for the agent to read after compose exits.

Mirrors the architecture of labs/ebpf-verify/agent/ebpf_line_collector.py
but adapted for production: phases 1 (ground truth) and 6 (comparison) are
omitted — the sidecar only traces, parses, and writes.

Environment variables
---------------------
COVERAGE_DIR    Directory to write ebpf_coverage.json  (default: /coverage)
LANGUAGE        Runtime hint: auto|python|java|node|go|ruby|generic  (default: auto)
TRAFFIC_WAIT    Seconds to collect after probe attaches  (default: 30)
TARGET_SERVICE  Name of the target service  (informational, default: target)

Output — NormalisedCoverage schema (matches coverage_normaliser.py)
--------------------------------------------------------------------
{
  "runtime": "python",
  "files": {
    "/app/views.py": {
      "executed_lines": [10, 11, 15],
      "executed_functions": ["index", "add_user"]
    }
  }
}

On unrecoverable error writes:
  {"skip": true, "skip_reason": "<reason>", "runtime": "<detected>"}

Exit codes
----------
0  Success — JSON written (may have zero files if nothing was traced)
1  Fatal — PID not found or bpftrace crashed at startup
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

COVERAGE_DIR   = Path(os.environ.get("COVERAGE_DIR",   "/coverage"))
LANGUAGE       = os.environ.get("LANGUAGE",       "auto").lower()
TRAFFIC_WAIT   = int(os.environ.get("TRAFFIC_WAIT", "30"))
TARGET_SERVICE = os.environ.get("TARGET_SERVICE",  "target")

BPFTRACE_SCRIPT = Path("/tmp/vulnreach_probe.bt")

# ── Phase 1: PID discovery ────────────────────────────────────────────────────

def _read_proc_text(pid: int, field: str) -> str:
    try:
        return (
            Path(f"/proc/{pid}/{field}")
            .read_bytes()
            .replace(b"\x00", b" ")
            .decode("utf-8", errors="replace")
            .strip()
        )
    except Exception:
        return ""


def find_target_pid() -> int | None:
    """Find the main application process PID in the shared PID namespace.

    Since we run with pid: "service:<target>", the target container's
    processes are directly visible.  We score each process and return the
    most likely application PID.

    Mirrors labs/ebpf-verify/agent/ebpf_line_collector.py::find_target_pid()
    but uses /proc scanning instead of pgrep for broader compatibility.
    """
    print(f"=== Phase 1: Discovering target PID (service={TARGET_SERVICE}) ===")

    _skip_names = {"bash", "sh", "dash", "sleep", "pause", "init", "tini", "dumb-init", "s6"}
    _app_names  = {
        "python3", "python", "java", "node", "nodejs",
        "ruby", "gunicorn", "uvicorn", "flask", "go",
    }

    candidates: list[tuple[int, str, int]] = []  # (pid, cmdline, score)

    for pid_dir in sorted(Path("/proc").glob("[0-9]*"), key=lambda p: int(p.name)):
        try:
            pid = int(pid_dir.name)
            if pid <= 1:
                continue
            cmdline = _read_proc_text(pid, "cmdline")
            if not cmdline:
                continue  # kernel thread or zombie

            try:
                exe = Path(f"/proc/{pid}/exe").resolve().name.lower()
            except Exception:
                exe = cmdline.split()[0].rsplit("/", 1)[-1].lower()

            score = 0
            if exe in _app_names or any(n in exe for n in _app_names):
                score += 3
            if exe in _skip_names:
                score -= 5

            # Prefer direct children of PID 1 (target's init)
            status = _read_proc_text(pid, "status")
            ppid_m = re.search(r"PPid:\s+(\d+)", status)
            if ppid_m and int(ppid_m.group(1)) == 1:
                score += 2

            candidates.append((pid, cmdline[:120], score))
        except Exception:
            continue

    if not candidates:
        print("  ERROR: No user processes found in shared PID namespace")
        print("  Is pid: \"service:<target>\" set in the compose override?")
        return None

    candidates.sort(key=lambda x: x[2], reverse=True)
    best_pid, best_cmd, best_score = candidates[0]
    print(f"  Selected PID {best_pid} (score={best_score:+d}): {best_cmd[:80]}")

    if len(candidates) > 1:
        print("  Top candidates:")
        for pid, cmd, score in candidates[:5]:
            print(f"    PID {pid:6d}  score={score:+d}  {cmd[:70]}")

    return best_pid


# ── Phase 2: Runtime detection ────────────────────────────────────────────────

def detect_runtime(pid: int) -> str:
    """Return the runtime name for the target PID.

    Mirrors labs/ebpf-verify/agent/ebpf_line_collector.py phase detection
    but supports all runtimes, not just Python.
    """
    if LANGUAGE != "auto":
        print(f"=== Phase 2: Runtime = {LANGUAGE} (from LANGUAGE env) ===")
        return LANGUAGE

    print(f"=== Phase 2: Auto-detecting runtime for PID {pid} ===")

    # Strategy 1: exe basename
    try:
        exe = Path(f"/proc/{pid}/exe").resolve().name.lower()
        for keyword, runtime in [
            ("python", "python"), ("java", "java"),
            ("node", "node"), ("ruby", "ruby"),
        ]:
            if keyword in exe:
                print(f"  Detected: {runtime}  (exe={exe})")
                return runtime
    except Exception:
        pass

    # Strategy 2: shared library maps
    try:
        maps = Path(f"/proc/{pid}/maps").read_text(errors="replace")
        checks = [
            ("libjvm.so", "java"), ("hotspot", "java"),
            ("libpython", "python"), ("/python3.", "python"),
            ("libnode.so", "node"),
            ("libruby", "ruby"),
        ]
        for marker, runtime in checks:
            if marker in maps:
                print(f"  Detected: {runtime}  ({marker} in /proc/{pid}/maps)")
                return runtime
    except Exception:
        pass

    # Strategy 3: cmdline keywords
    cmdline = _read_proc_text(pid, "cmdline").lower()
    for keyword, runtime in [
        ("python", "python"), ("java", "java"),
        ("node", "node"), ("ruby", "ruby"),
    ]:
        if keyword in cmdline:
            print(f"  Detected: {runtime}  (cmdline match)")
            return runtime

    print("  Detected: generic  (no runtime clues found)")
    return "generic"


# ── Phase 3: Probe selection and bpftrace start ───────────────────────────────

def _has_python_usdt(pid: int) -> bool:
    """Return True if /proc/{pid}/exe has stapsdt USDT notes for python.

    ubuntu:22.04 Python has these; python:3.x-slim (Debian) does not.
    Matches the readelf assertion in labs/ebpf-verify/target/Dockerfile.
    """
    try:
        result = subprocess.run(
            ["readelf", "-n", f"/proc/{pid}/exe"],
            capture_output=True, text=True, timeout=5,
        )
        return "stapsdt" in result.stdout and "python" in result.stdout.lower()
    except Exception:
        return False


def _find_libjvm(pid: int) -> str | None:
    """Return absolute path of libjvm.so for *pid* by scanning /proc/{pid}/maps."""
    try:
        maps = Path(f"/proc/{pid}/maps").read_text(errors="replace")
        for line in maps.splitlines():
            if "libjvm.so" in line:
                return line.split()[-1]
    except Exception:
        pass
    return None


def _has_java_hotspot(libjvm_path: str) -> bool:
    """Return True if libjvm.so exposes hotspot:method__entry USDT probes."""
    try:
        result = subprocess.run(
            ["readelf", "-n", libjvm_path],
            capture_output=True, text=True, timeout=5,
        )
        return "hotspot" in result.stdout and "method__entry" in result.stdout
    except Exception:
        return False


def build_probe_script(pid: int, runtime: str) -> tuple[str, str]:
    """Return (bpftrace_script, output_parser_name).

    Tries higher-fidelity probes first, degrades to openat if unavailable.
    openat is always available on kernels >= 4.9 and traces the full process
    tree by walking task->real_parent up to 10 levels (catches gunicorn/uWSGI
    worker forks).
    """
    if runtime == "python" and _has_python_usdt(pid):
        print(f"  Probe: usdt python:line  (USDT probes confirmed on PID {pid})")
        script = (
            f"usdt:/proc/{pid}/exe:python:line\n"
            "{\n"
            '  printf("line:%s:%d\\n", str(arg0), (int64)arg2);\n'
            "}\n"
        )
        return script, "python_line"

    if runtime in ("java", "auto"):
        libjvm = _find_libjvm(pid)
        if libjvm and _has_java_hotspot(libjvm):
            print(f"  Probe: usdt hotspot:method__entry  (USDT confirmed on PID {pid})")
            script = (
                f"usdt:{libjvm}:hotspot:method__entry\n"
                "{\n"
                '  printf("method:%s:%s\\n", str(arg1), str(arg2));\n'
                "}\n"
            )
            return script, "java_method"
        if runtime == "java":
            print("  Probe: openat  (hotspot USDT unavailable — add -XX:+ExtendedDTraceProbes)")

    if runtime == "python":
        print("  Probe: openat  (python binary has no USDT probes — use ubuntu:22.04 target for line coverage)")
    elif runtime not in ("java", "auto"):
        print(f"  Probe: openat  (runtime={runtime})")

    script = (
        "tracepoint:syscalls:sys_enter_openat\n"
        "{\n"
        f"  $target = (uint64){pid};\n"
        "  $t = curtask;\n"
        "  $found = (uint8)0;\n"
        "  unroll(10) {\n"
        "    if ($t->tgid == $target) { $found = 1; }\n"
        "    $t = $t->real_parent;\n"
        "  }\n"
        "  if ($found) {\n"
        '    printf("open:%s\\n", str(args->filename));\n'
        "  }\n"
        "}\n"
    )
    return script, "openat"


def start_bpftrace(script: str) -> subprocess.Popen:
    """Write script to /tmp, start bpftrace, verify it attaches successfully.

    Mirrors labs/ebpf-verify/agent/ebpf_line_collector.py::start_bpftrace():
    1.5 s pause + immediate poll to catch permission errors and missing
    tracepoints before we start waiting for traffic.
    """
    BPFTRACE_SCRIPT.write_text(script, encoding="utf-8")
    print(f"  Script: {BPFTRACE_SCRIPT}")

    proc = subprocess.Popen(
        ["bpftrace", str(BPFTRACE_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Give bpftrace time to attach probe, then check it hasn't already crashed.
    time.sleep(1.5)
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"bpftrace exited immediately (rc={proc.returncode}): {stderr}"
        )

    print(f"  bpftrace attached  (pid={proc.pid})")
    return proc


# ── Phase 4: Wait for traffic ─────────────────────────────────────────────────

def wait_for_traffic() -> None:
    """Block for TRAFFIC_WAIT seconds while Schemathesis drives traffic."""
    print(f"=== Phase 4: Collecting for {TRAFFIC_WAIT}s (Schemathesis traffic window) ===")
    time.sleep(TRAFFIC_WAIT)


# ── Phase 5: Collect, parse, write JSON ──────────────────────────────────────

_NOISE_PREFIXES = ("/proc/", "/sys/", "/dev/", "/run/", "/tmp/", "/etc/")
_SOURCE_EXTS = {
    ".py", ".rb", ".js", ".ts", ".java", ".go",
    ".php", ".rs", ".cs", ".cpp", ".c", ".h",
}


def _is_source_path(path: str) -> bool:
    if any(path.startswith(p) for p in _NOISE_PREFIXES):
        return False
    ext = os.path.splitext(path)[1]
    return ext in _SOURCE_EXTS or not ext


def collect_output(proc: subprocess.Popen) -> str:
    """Terminate bpftrace and return its stdout."""
    print("=== Phase 5: Stopping tracer, parsing output ===")
    proc.terminate()
    try:
        stdout, stderr = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    raw = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace").strip()

    event_count = sum(
        1 for row in raw.splitlines()
        if row.strip() and not row.startswith("Attaching")
    )
    print(f"  bpftrace emitted {event_count} raw event line(s)")

    if err:
        for line in err.splitlines()[:10]:
            print(f"  [bpftrace stderr] {line}")

    if event_count == 0:
        print(
            "  WARNING: Zero events captured. Possible causes:\n"
            "    (1) probe did not attach — check [bpftrace stderr] above\n"
            "    (2) no traffic reached the target during collection window\n"
            "    (3) USDT probes absent — python:line needs CPython --with-dtrace\n"
            "        (ubuntu:22.04 has them; python:3.x-slim does not)\n"
            "    (4) /sys/kernel/debug not bind-mounted into the sidecar container"
        )

    return raw


def parse_output(raw: str, parser: str, runtime: str) -> dict:
    """Parse bpftrace stdout into NormalisedCoverage format."""
    hits: dict[str, dict] = defaultdict(lambda: {"lines": set(), "funcs": set()})

    if parser == "python_line":
        pattern = re.compile(r"^line:(.+):(\d+)$")
        for row in raw.splitlines():
            m = pattern.match(row.strip())
            if m:
                hits[m.group(1)]["lines"].add(int(m.group(2)))

    elif parser == "java_method":
        # Input: "method:com/example/Foo:bar"
        # Resolving to line numbers requires javap; store function-level coverage
        # which is sufficient for DYNAMICALLY_REACHABLE correlation.
        pattern = re.compile(r"^method:(.+):(.+)$")
        for row in raw.splitlines():
            m = pattern.match(row.strip())
            if m:
                class_slash, method = m.group(1), m.group(2)
                hits[class_slash + ".java"]["funcs"].add(method)

    elif parser == "openat":
        pattern = re.compile(r"^open:(.+)$")
        for row in raw.splitlines():
            m = pattern.match(row.strip())
            if m and _is_source_path(m.group(1)):
                hits[m.group(1)]  # register the file, no lines

    files: dict[str, dict] = {
        fp: {
            "executed_lines": sorted(data["lines"]),
            "executed_functions": sorted(data["funcs"]),
        }
        for fp, data in hits.items()
    }
    return {"runtime": runtime, "files": files}


def write_coverage(data: dict) -> None:
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = COVERAGE_DIR / "ebpf_coverage.json"
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    file_count = len(data.get("files", {}))
    line_count = sum(len(f["executed_lines"])   for f in data.get("files", {}).values())
    func_count = sum(len(f["executed_functions"]) for f in data.get("files", {}).values())
    print(f"  Written: {out_path}")
    print(f"  files={file_count}  lines={line_count}  functions={func_count}  runtime={data.get('runtime')}")


def write_skip(reason: str, runtime: str = "unknown") -> None:
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = COVERAGE_DIR / "ebpf_coverage.json"
    out_path.write_text(
        json.dumps({"skip": True, "skip_reason": reason, "runtime": runtime}, indent=2),
        encoding="utf-8",
    )
    print(f"  Skip written ({reason}): {out_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(
        f"VulnReach eBPF sidecar — "
        f"target={TARGET_SERVICE}  language={LANGUAGE}  traffic_wait={TRAFFIC_WAIT}s"
    )
    print(f"Coverage dir: {COVERAGE_DIR}")
    print()

    # Phase 1
    pid = find_target_pid()
    if pid is None:
        write_skip("no_pid_found")
        sys.exit(1)

    # Phase 2
    print()
    runtime = detect_runtime(pid)

    # Phase 3
    print("=== Phase 3: Selecting and attaching bpftrace probe ===")
    script, parser = build_probe_script(pid, runtime)
    try:
        tracer = start_bpftrace(script)
    except RuntimeError as exc:
        print(f"  FATAL: {exc}")
        write_skip("bpftrace_startup_failed", runtime)
        sys.exit(1)

    # Phase 4
    print()
    wait_for_traffic()

    # Phase 5
    print()
    raw     = collect_output(tracer)
    data    = parse_output(raw, parser, runtime)
    write_coverage(data)

    print()
    print("VulnReach eBPF sidecar complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
