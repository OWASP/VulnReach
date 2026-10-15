"""Deterministic call-count workloads for measuring Tier B uprobe overhead.

Runs *inside* the target container and times itself, so the numbers exclude
`docker exec` and observer-startup cost — the only difference between runs is
whether a uprobe is attached to this interpreter's eval loop.

Two shapes, because CPython enters `_PyEval_EvalFrameDefault` very differently
depending on who is calling:

  py_to_py  a Python function calling a Python function. On CPython >= 3.11 the
            CALL opcode pushes the new frame and jumps inside the *same* eval
            loop invocation, so the uprobe never fires. On <= 3.10 every call
            re-enters the function, so every call traps.
  c_to_py   a Python function called from C (`map`). This always goes through
            _PyFunction_Vectorcall -> _PyEval_Vector -> _PyEval_EvalFrameDefault,
            on every version, so every iteration traps.

Reporting ns/call for both therefore separates "cost per trap" from "how often
we actually trap", which is what decides whether Rule R5 needs mitigation.
"""
from __future__ import annotations

import json
import sys
import time


def leaf(x):
    return x + 1


def py_to_py(n):
    for i in range(n):
        leaf(i)


def c_to_py(n):
    for _ in map(leaf, range(n)):
        pass


def bench(fn, n, reps):
    runs = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn(n)
        runs.append(time.perf_counter_ns() - t0)
    runs.sort()
    return {
        "min_ns": runs[0],
        "median_ns": runs[len(runs) // 2],
        # min is the honest estimate: noise only ever adds time.
        "ns_per_call": round(runs[0] / n, 2),
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
    reps = int(sys.argv[2]) if len(sys.argv) > 2 else 7
    print(json.dumps({
        "python": "%d.%d" % sys.version_info[:2],
        "n": n,
        "reps": reps,
        "py_to_py": bench(py_to_py, n, reps),
        "c_to_py": bench(c_to_py, n, reps),
    }))
