#!/usr/bin/env python3
"""Phase 1B.1 benchmark: separated setup / prove / verify processes.

For each cap, setup runs once.  Each (cap, density) case then runs prove and
verify as two independent processes; the verifier receives only setup.json,
proof bytes, public.json and never any graph/witness file.

Reported columns:
  params_gen_ms / vk_gen_ms / pk_gen_ms  -- from setup, one-time per cap
  prove_ms                                -- pure create_proof, from prover
  pure_verify_ms                          -- verify_proof only, from verifier
  vk_rebuild_ms                           -- verifier VK reconstruction (excluded)
  sig_verify_ms                           -- collector signature check (excluded)
  peak_*_mb                               -- Windows PeakWorkingSetSize per process
"""

from __future__ import annotations

import ctypes
import json
import re
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "halo2" / "target" / "release" / "zk-agent-ifc-audit-halo2.exe"
RAW = ROOT / "experiments" / "phase1b1" / "raw"
ALL_CAPS = [50, 100, 200]
ARGS = sys.argv[1:]
REPORT_ONLY = "--report-only" in ARGS
CAPS = [int(x) for x in ARGS if x.isdigit()] or ALL_CAPS
DENSITIES = ["low", "mid", "high"]
SEEDS = {50: 2026112601, 100: 2026112604, 200: 2026112607}


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


def run_monitored(cmd: list[str]) -> dict:
    started = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peak = 0
    while proc.poll() is None:
        value = peak_working_set(proc.pid)
        if value:
            peak = max(peak, value)
        time.sleep(0.01)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"command failed: {cmd}\nstderr={stderr}\nstdout={stdout}")
    return {
        "wall_ms": int((time.perf_counter() - started) * 1000),
        "peak_mb": round(peak / (1024 * 1024), 2) if peak else None,
        "stdout": stdout.strip(),
    }


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    setups: dict[int, dict] = {}

    for cap in ([] if REPORT_ONLY else CAPS):
        setup_path = RAW / f"setup{cap}.json"
        print(f"[setup] cap={cap}", flush=True)
        setup_run = run_monitored([str(BIN), "setup", str(cap), str(setup_path)])
        setup_data = json.loads(setup_path.read_text(encoding="utf-8"))
        setup_data["setup_wall_ms"] = setup_run["wall_ms"]
        setup_data["setup_peak_mb"] = setup_run["peak_mb"]
        setup_path.write_text(json.dumps(setup_data, indent=2, ensure_ascii=False), encoding="utf-8")
        setups[cap] = setup_data

        selftest = run_monitored([str(BIN), "selftest", str(cap)])
        selftest_data = json.loads(selftest["stdout"].splitlines()[-1])
        (RAW / f"selftest{cap}.json").write_text(
            json.dumps(selftest_data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        for idx, density in enumerate(DENSITIES):
            seed = SEEDS[cap] + idx
            proof_path = RAW / f"cap{cap}_{density}.proof"
            public_path = RAW / f"cap{cap}_{density}.public.json"
            verify_path = RAW / f"cap{cap}_{density}.verify.json"
            print(f"  [prove] cap={cap} density={density}", flush=True)
            prove_run = run_monitored([
                str(BIN), "prove", str(cap), density, str(seed),
                str(setup_path), str(proof_path), str(public_path),
            ])
            print(f"  [verify] cap={cap} density={density}", flush=True)
            verify_run = run_monitored([
                str(BIN), "verify", str(setup_path), str(proof_path),
                str(public_path), str(verify_path),
            ])
            public = json.loads(public_path.read_text(encoding="utf-8"))
            verified = json.loads(verify_path.read_text(encoding="utf-8"))
            row = dict(public)
            row.update(verified)
            row.update({
                "params_gen_ms": setup_data["params_gen_ms"],
                "vk_gen_ms": setup_data["vk_gen_ms"],
                "pk_gen_ms": setup_data["pk_gen_ms"],
                "prove_peak_mb": prove_run["peak_mb"],
                "prove_wall_ms": prove_run["wall_ms"],
                "verify_peak_mb": verify_run["peak_mb"],
                "verify_wall_ms": verify_run["wall_ms"],
                "selftest": selftest_data,
            })
            (RAW / f"cap{cap}_{density}.json").write_text(
                json.dumps(row, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            rows.append(row)

    lines = [
        "# Phase 1B.1 实测结果（固定电路 / 独立验证者 / 盲化承诺）",
        "",
        "一次性 setup 按 cap 生成；每个 cap/density 的 prove 与 verify 为两个独立进程。",
        "verifier 只读取 setup.json、proof、public.json，不读取任何图或 witness 文件。",
        "",
        "## Setup（每 cap 一次）",
        "",
        "| cap | k | params_gen_ms | vk_gen_ms | pk_gen_ms | setup_peak_MB |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    all_setups = {}
    for cap in ALL_CAPS:
        path = RAW / f"setup{cap}.json"
        if path.exists():
            all_setups[cap] = json.loads(path.read_text(encoding="utf-8"))
    for cap in ALL_CAPS:
        if cap not in all_setups:
            continue
        s = all_setups[cap]
        lines.append(
            f"| {cap} | {s['k']} | {s['params_gen_ms']} | {s['vk_gen_ms']} | "
            f"{s['pk_gen_ms']} | {s['setup_peak_mb']} |"
        )
    lines += [
        "",
        "## Prove / Verify（每 case 独立进程）",
        "",
        "| cap | density | active | proof_B | prove_ms | pure_verify_ms | vk_rebuild_ms | "
        "sig_verify_ms | prove_peak_MB | verify_peak_MB |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    row_pattern = re.compile(r"^cap(50|100|200)_(low|mid|high)\.json$")
    row_files = sorted(p for p in RAW.glob("*.json") if row_pattern.match(p.name))
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in row_files]
    rows.sort(key=lambda r: (ALL_CAPS.index(r["cap"]), DENSITIES.index(r["density"])))
    for r in rows:
        lines.append(
            f"| {r['cap']} | {r['density']} | {r['active_edges']} | {r['proof_bytes']} | "
            f"{r['prove_ms']} | {r['pure_verify_ms']} | {r['vk_rebuild_ms']} | "
            f"{r['sig_verify_ms']} | {r['prove_peak_mb']} | {r['verify_peak_mb']} |"
        )
    lines += [
        "",
        "说明：",
        "- `pure_verify_ms` 只含 `verify_proof`，不含 VK 重建、签名验证或文件读取。",
        "- `vk_rebuild_ms` 是验证者从公开固定模板重建 VK 的时间（halo2 0.4 无 VK 序列化 API）。",
        "- `prove_ms` 只含 `create_proof`，不含 setup 与 witness 生成。",
        "- 峰值内存为 Windows `PeakWorkingSetSize` 采样值。",
        "- 验证者还会重新生成公开 Params（不计入 `pure_verify_ms`）；`verify_wall_ms` 含该项。",
        "- cap=200 的 MockProver 自检因 2^19 域过大而跳过，由真实 prove/verify 覆盖。",
        "- 与 1B 基线的 `verify_ms`（含 keygen_vk）不可直接比较；见 `docs/DECISION_GATE.md`。",
    ]
    (ROOT / "experiments" / "phase1b1" / "RESULTS.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))


if __name__ == "__main__":
    main()
