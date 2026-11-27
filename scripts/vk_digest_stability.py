#!/usr/bin/env python3
"""Phase 1B.1.3 C: VK digest stability audit (cap=50 only).

Runs setup(50) three times as independent processes and compares vk_digest and
vk_hash.  This checks within-build repeatability only; it does NOT establish
cross-compiler or cross-dependency-version stability of the Debug-derived
digest.  All outputs go to experiments/phase1b1_3/raw/.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "halo2" / "target" / "release" / "zk-agent-ifc-audit-halo2.exe"
RAW = ROOT / "experiments" / "phase1b1_3" / "raw"


def run_setup(name: str) -> dict:
    out = RAW / f"vk_stability_{name}.json"
    started = time.perf_counter()
    proc = subprocess.run([str(BIN), "setup", "50", str(out)],
                          capture_output=True, text=True)
    data = json.loads(out.read_text(encoding="utf-8"))
    data["_exit_code"] = proc.returncode
    data["_harness_wall_ms"] = int((time.perf_counter() - started) * 1000)
    return data


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    runs = [run_setup(f"run{i}") for i in (1, 2, 3)]
    digests = [r["vk_digest"] for r in runs]
    hashes = [r["vk_hash"] for r in runs]
    result = {
        "schema": "ifc-fixed-v1",
        "cap": 50,
        "runs": [
            {
                "vk_digest": r["vk_digest"],
                "vk_hash": r["vk_hash"],
                "k": r["k"],
                "circuit_version": r["circuit_version"],
                "params_gen_ms": r["params_gen_ms"],
                "vk_gen_ms": r["vk_gen_ms"],
                "exit_code": r["_exit_code"],
            }
            for r in runs
        ],
        "vk_digest_stable_within_build": len(set(digests)) == 1,
        "vk_hash_stable_within_build": len(set(hashes)) == 1,
        "distinct_digests": len(set(digests)),
        "note": (
            "vk_digest = SHA256 of format!(\"{:?}\", vk.pinned()). "
            "This is a pinned-build prototype digest: format Debug is not a "
            "canonical/cross-version serialization. Stability shown here is "
            "within one binary + dependency set only; cross-compiler and "
            "cross-dependency-version compatibility is NOT established."
        ),
    }
    (RAW / "vk_digest_stability.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps({
        "vk_digest_stable_within_build": result["vk_digest_stable_within_build"],
        "vk_hash_stable_within_build": result["vk_hash_stable_within_build"],
        "distinct_digests": result["distinct_digests"],
    }))


if __name__ == "__main__":
    main()
