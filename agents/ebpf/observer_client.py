"""Async client for the VulnReach eBPF observer binary (P0, D8).

Spawns the standalone Go/cilium-ebpf observer as a subprocess, blocks until it
emits the ``ready`` control line (replacing the old sleep-and-poll attach check),
then streams parsed NDJSON events until ``summary`` or ``stop()``.

The observer emits one JSON object per line on stdout. Control lines carry
``type`` in {ready, error, summary}; event lines carry ``type`` == "exec" (P0).
See docs/ebpf-p0-spec.md §5.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
from typing import Any, Optional

_DEFAULT_BIN = os.environ.get(
    "VULNREACH_OBSERVER_BIN",
    os.path.join(os.path.dirname(__file__), "observer", "bin", "vulnreach-observer"),
)


class ObserverError(RuntimeError):
    pass


class ObserverClient:
    """Drive the observer binary and collect its NDJSON event stream."""

    def __init__(self, binary_path: str = _DEFAULT_BIN):
        self._bin = binary_path
        self._proc: Optional[asyncio.subprocess.Process] = None

    async def start(self, cgroup_ids: list[int], duration: int = 0,
                    ready_timeout: float = 10.0,
                    python_lib: Optional[str] = None,
                    jvm_lib: Optional[str] = None) -> dict[str, Any]:
        """Spawn the observer and return the parsed ``ready`` line.

        ``python_lib`` / ``jvm_lib`` enable Tier B enrichment (the CPython uprobe
        for Rule R5, the JVM class__loaded USDT probe for Rule R6).
        It is best-effort: an unusable path makes the observer emit a ``warn``
        and carry on with the Tier A baseline, never an ``error``.

        Raises ObserverError if the binary emits an ``error`` line, dies before
        ``ready``, or does not become ready within ``ready_timeout`` seconds.
        """
        if not os.path.exists(self._bin):
            raise ObserverError(f"observer binary not found: {self._bin}")

        args = [self._bin]
        for cid in cgroup_ids:
            args += ["--cgroup-id", str(cid)]
        if duration:
            args += ["--duration", str(duration)]
        if python_lib:
            args += ["--python-lib", python_lib]
        if jvm_lib:
            args += ["--jvm-lib", jvm_lib]

        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,   # control channel (see `mark`)
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # `warn` lines legitimately precede `ready` — a best-effort probe that
        # failed to attach (e.g. openat2 on an old kernel, or Tier B) reports it
        # and the observer carries on. Consume them until ready/error.
        warnings: list[str] = []

        async def _await_ready() -> Optional[dict]:
            while True:
                line = await self._read_json()
                if line is None or line.get("type") != "warn":
                    return line
                warnings.append(str(line.get("msg", "")))

        try:
            line = await asyncio.wait_for(_await_ready(), timeout=ready_timeout)
        except asyncio.TimeoutError:
            await self.stop()
            raise ObserverError("observer did not emit 'ready' within timeout")

        if line is None:
            stderr = (await self._proc.stderr.read()).decode(errors="replace")
            raise ObserverError(f"observer exited before ready; stderr: {stderr.strip()}")
        if line.get("type") == "error":
            raise ObserverError(f"observer error: {line.get('msg')}")
        if line.get("type") != "ready":
            raise ObserverError(f"expected 'ready', got: {line}")
        line["warnings"] = warnings
        return line

    def mark(self) -> None:
        """Tell the observer that real traffic is starting.

        Bumps the Tier B dedupe epoch so files already reported during startup
        can be reported once more while handling requests — without it, the
        per-file dedupe hides exactly the frames Rule R5 cares about.
        Best-effort and non-blocking; a dead observer is not an error here.
        """
        if self._proc and self._proc.stdin and not self._proc.stdin.is_closing():
            try:
                self._proc.stdin.write(b"mark\n")
            except (BrokenPipeError, ConnectionResetError):
                pass

    async def events(self):
        """Async-iterate parsed event dicts until the stream ends or summary."""
        assert self._proc is not None
        while True:
            line = await self._read_json()
            if line is None:
                return
            t = line.get("type")
            if t == "summary":
                self._summary = line
                return
            if t == "error":
                raise ObserverError(f"observer error mid-stream: {line.get('msg')}")
            if t in ("warn", "marked"):
                continue  # control lines, not events
            yield line

    async def collect(self) -> list[dict[str, Any]]:
        """Convenience: drain all events into a list (until summary/exit)."""
        return [e async for e in self.events()]

    async def stop(self) -> None:
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.send_signal(signal.SIGTERM)
                await asyncio.wait_for(self._proc.wait(), timeout=10)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    self._proc.kill()
                except ProcessLookupError:
                    pass

    async def _read_json(self) -> Optional[dict[str, Any]]:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            raw = await self._proc.stdout.readline()
            if not raw:
                return None
            s = raw.decode(errors="replace").strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                continue
            if obj.get("v") != 1:
                # forward-compat: ignore unknown schema versions
                continue
            return obj
