#!/usr/bin/env python3
"""Run Phase 1B Halo2 benchmark cases and record metrics with peak memory."""

from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "halo2" / "target" / "release" / "zk-agent-ifc-audit-halo2.exe"
RAW = ROOT / "experiments" / "phase1b" / "raw"
CASES = [
    (50, "low", 2026112601),
    (50, "mid", 2026112602),
    (50, "high", 2026112603),
    (100, "low", 2026112604),
    (100, "mid", 2026112605),
    (100, "high", 2026112606),
    (200, "low", 2026112607),
    (200, "mid", 2026112608),
    (200, "high", 2026112609),
]


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def peak_working_set(pid: int) -> int | None:
    if sys.platform != "win32":
        return None
    process = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not process:
        return None
    try:
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(
            process, ctypes.byref(counters), counters.cb
        )
        return int(counters.PeakWorkingSetSize) if ok else None
    finally:
        ctypes.windll.kernel32.CloseHandle(process)


def run_case(cap: int, density: str, seed: int) -> dict:
    out = RAW / f"cap{cap}_{density}.json"
    cmd = [str(BIN), str(cap), density, str(seed), str(out)]
    started = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peak = 0
    while proc.poll() is None:
        value = peak_working_set(proc.pid)
        if value:
            peak = max(peak, value)
        time.sleep(0.01)
    stdout, stderr = proc.communicate()
    wall_ms = int((time.perf_counter() - started) * 1000)
    if proc.returncode != 0:
        raise RuntimeError(f"case {cap}/{density} failed: {stderr}\n{stdout}")
    data = json.loads(out.read_text(encoding="utf-8"))
    data["harness_wall_ms"] = wall_ms
    data["peak_working_set_mb"] = round(peak / (1024 * 1024), 2) if peak else None
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return data


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    rows = []
    for cap, density, seed in CASES:
        print(f"running cap={cap} density={density} seed={seed}", flush=True)
        rows.append(run_case(cap, density, seed))
    header = [
        "| cap | density | active_edges | k | perms | prove_ms | verify_ms | proof_B | peak_MB |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        header.append(
            f"| {r['cap']} | {r['density']} | {r['active_edges']} | {r['k']} | "
            f"{r['poseidon_permutations']} | {r['prove_ms']} | {r['verify_ms']} | "
            f"{r['proof_bytes']} | {r['peak_working_set_mb']} |"
        )
    header += [
        "",
        "说明：perms = Poseidon 置换次数（node/edge leaf 各 2，empty/merge 各 1）；"
        "peak_MB = Windows PeakWorkingSetSize 采样值。",
        "halo2_proofs 0.4 不公开精确全局约束数，不编造数字；gate 声明数与约束多项式数见 raw JSON。",
    ]
    (ROOT / "experiments" / "phase1b" / "RESULTS.md").write_text(
        "# Phase 1B 实测结果\n\n" + "\n".join(header) + "\n", encoding="utf-8"
    )
    print("\n".join(header))


if __name__ == "__main__":
    main()
