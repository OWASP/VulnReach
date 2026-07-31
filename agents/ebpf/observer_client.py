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
                    ready_timeout: float = 10.0) -> dict[str, Any]:
        """Spawn the observer and return the parsed ``ready`` line.

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

        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            line = await asyncio.wait_for(self._read_json(), timeout=ready_timeout)
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
        return line

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
