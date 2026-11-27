#!/usr/bin/env python3
"""Phase 1B.1.3: independent reproduction of the cap=50 soundness build.

This script NEVER touches Phase 1B / 1B.1 / 1B.1.2 raw data.  All outputs go to
experiments/phase1b1_3/raw/.  For every process invocation the full stdout and
the exit code are persisted, so REPRODUCTION_LOG.md can quote raw evidence.

Scope: cap=50 only.  No cap expansion, no new circuits, no recursive proofs.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from run_phase1b1 import peak_working_set

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "halo2" / "target" / "release" / "zk-agent-ifc-audit-halo2.exe"
RAW = ROOT / "experiments" / "phase1b1_3" / "raw"
ALLOWLIST = ROOT / "config" / "trusted_collectors.test.json"

CAP = 50
DENSITIES = ["low", "mid", "high"]
SEEDS = {"low": 2026112601, "mid": 2026112602, "high": 2026112603}
NEG_CASES = ["illegal_ifc", "node_tl_mismatch", "edge_idx_mismatch", "crossbar_prev_dst"]
TEST_SK = bytes([0x11] * 32)
ATTACKER_SK = bytes([0x22] * 32)


def run_monitored(cmd: list[str]) -> dict:
    # Use temp files instead of subprocess.PIPE.  A child that writes more
    # than the OS pipe buffer (e.g. the 16-case attack JSON, ~7 KB) blocks on
    # write while this parent waits in poll() without draining the pipe; that
    # deadlocks.  Files have no such buffer limit.
    import tempfile
    started = time.perf_counter()
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as fo, \
         tempfile.TemporaryFile(mode="w+", encoding="utf-8") as fe:
        proc = subprocess.Popen(cmd, stdout=fo, stderr=fe)
        peak = 0
        while proc.poll() is None:
            value = peak_working_set(proc.pid)
            if value:
                peak = max(peak, value)
            time.sleep(0.01)
        exit_code = proc.returncode
        fo.seek(0); stdout = fo.read()
        fe.seek(0); stderr = fe.read()
    return {
        "cmd": cmd,
        "exit_code": exit_code,
        "wall_ms": int((time.perf_counter() - started) * 1000),
        "peak_mb": round(peak / (1024 * 1024), 2) if peak else None,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
    }


def save_run(name: str, run: dict) -> None:
    (RAW / f"{name}.log").write_text(
        "\n".join([
            f"command: {' '.join(run['cmd'])}",
            f"exit_code: {run['exit_code']}",
            f"wall_ms: {run['wall_ms']}",
            f"peak_mb: {run['peak_mb']}",
            "--- stdout ---",
            run["stdout"],
            "--- stderr ---",
            run["stderr"],
        ]),
        encoding="utf-8",
    )


def last_json(stdout: str) -> dict:
    return json.loads(stdout.strip().splitlines()[-1])


def sign_public(path: Path, sk_bytes: bytes) -> None:
    public = json.loads(path.read_text(encoding="utf-8"))
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    msg = "|".join(str(public[k]) for k in (
        "commitment", "policy_id", "session_id", "nonce", "collector_id"
    )).encode("ascii")
    public["collector_signature"] = sk.sign(msg).hex()
    path.write_text(json.dumps(public, indent=2, ensure_ascii=False), encoding="utf-8")


def collector_id(sk_bytes: bytes) -> int:
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big") & ((1 << 63) - 1)


def write_verify_case(name: str, public_path: Path, proof_path: Path) -> dict:
    verify_path = RAW / f"{name}.verify.json"
    run = run_monitored([
        str(BIN), "verify", str(RAW / "setup50.json"), str(ALLOWLIST),
        str(proof_path), str(public_path), str(verify_path),
    ])
    save_run(f"{name}_verify", run)
    v = json.loads(verify_path.read_text(encoding="utf-8"))
    v["_exit_code"] = run["exit_code"]
    return v


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)

    import platform as _platform
    import sys as _sys
    env = {
        "python": _sys.version,
        "pytest": getattr(__import__("pytest"), "__version__", "unavailable"),
        "cryptography": getattr(__import__("cryptography"), "__version__", "unavailable"),
        "os": _platform.platform(),
    }
    (RAW / "environment.json").write_text(
        json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # --- setup (corrected timing) ---
    setup_path = RAW / "setup50.json"
    run = run_monitored([str(BIN), "setup", str(CAP), str(setup_path)])
    save_run("setup50", run)
    setup = json.loads(setup_path.read_text(encoding="utf-8"))
    setup["setup_wall_ms"] = run["wall_ms"]
    setup["setup_peak_mb"] = run["peak_mb"]
    setup_path.write_text(json.dumps(setup, indent=2, ensure_ascii=False), encoding="utf-8")

    # --- selftest (MockProver ground truth) ---
    run = run_monitored([str(BIN), "selftest", str(CAP)])
    save_run("selftest50", run)
    (RAW / "selftest50.json").write_text(
        json.dumps(last_json(run["stdout"]), indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # --- 16-case MockProver attack suite (background truth, not proof layer) ---
    run = run_monitored([str(BIN), "attack", str(CAP)])
    save_run("attack50", run)
    (RAW / "attack50.json").write_text(
        json.dumps(last_json(run["stdout"]), indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # --- A2: three positive real proofs ---
    perf_rows: list[dict] = []
    for density in DENSITIES:
        seed = SEEDS[density]
        proof_path = RAW / f"cap50_{density}.proof"
        public_path = RAW / f"cap50_{density}.public.json"
        meta_path = RAW / f"cap50_{density}.meta.json"
        prove_run = run_monitored([
            str(BIN), "prove", str(CAP), density, str(seed), str(setup_path),
            str(proof_path), str(public_path), str(meta_path),
        ])
        save_run(f"prove50_{density}", prove_run)
        verify_run = run_monitored([
            str(BIN), "verify", str(setup_path), str(ALLOWLIST),
            str(proof_path), str(public_path), str(RAW / f"cap50_{density}.verify.json"),
        ])
        save_run(f"verify50_{density}", verify_run)
        public = json.loads(public_path.read_text(encoding="utf-8"))
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        verified = json.loads((RAW / f"cap50_{density}.verify.json").read_text(encoding="utf-8"))
        row = {
            "density": density,
            "active_edges": meta["active_edges"],
            "proof_bytes": public["proof_bytes"],
            "public_inputs": {
                "commitment": public["commitment"],
                "policy_id": public["policy_id"],
                "session_id": public["session_id"],
                "nonce": public["nonce"],
                "collector_id": public["collector_id"],
            },
            "witness_generation_ms": public["witness_generation_ms"],
            "params_generation_ms": public["params_generation_ms"],
            "vk_generation_ms": public["vk_generation_ms"],
            "pk_generation_ms": public["pk_generation_ms"],
            "create_proof_ms": public["create_proof_ms"],
            "keygen_reused_from_setup": public["keygen_reused_from_setup"],
            "prove_wall_ms": prove_run["wall_ms"],
            "prove_peak_mb": prove_run["peak_mb"],
            "prove_exit_code": prove_run["exit_code"],
            "params_generation_verify_ms": verified.get("params_generation_ms"),
            "collector_allowlist_lookup_ms": verified.get("collector_allowlist_lookup_ms"),
            "signature_verification_ms": verified.get("signature_verification_ms"),
            "vk_rebuild_ms": verified.get("vk_rebuild_ms"),
            "verify_proof_ms": verified.get("verify_proof_ms"),
            "verify_wall_ms": verify_run["wall_ms"],
            "verify_peak_mb": verify_run["peak_mb"],
            "verify_exit_code": verify_run["exit_code"],
            "wrong_nonce_rejected": verified.get("wrong_nonce_rejected"),
            "accepted": verified.get("accepted"),
        }
        perf_rows.append(row)
        (RAW / f"cap50_{density}.json").write_text(
            json.dumps(row, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # --- A3: four real proof-layer negatives ---
    proof_negatives: list[dict] = []
    for case in NEG_CASES:
        proof_path = RAW / f"neg_{case}.proof"
        public_path = RAW / f"neg_{case}.public.json"
        run = run_monitored([
            str(BIN), "prove-attack", str(CAP), case, str(setup_path),
            str(proof_path), str(public_path),
        ])
        save_run(f"neg_{case}_prove", run)
        prove_result = last_json(run["stdout"])
        accepted = None
        reason = prove_result.get("reason")
        if prove_result.get("create_proof_ok"):
            v = write_verify_case(f"neg_{case}", public_path, proof_path)
            accepted = v.get("accepted")
            reason = v.get("reason") or reason
            v["_stage"] = "verify"
            (RAW / f"neg_{case}.verify.json").write_text(
                json.dumps(v, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        proof_negatives.append({
            "case": case,
            "create_proof_ok": prove_result.get("create_proof_ok"),
            "proof_bytes": prove_result.get("proof_bytes"),
            "create_proof_exit_code": run["exit_code"],
            "verify_accepted": accepted,
            "reason": reason,
        })
    (RAW / "proof_layer_negatives.json").write_text(
        json.dumps(proof_negatives, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # --- A4: collector identity, five cases across three layers ---
    good_public = RAW / "cap50_low.public.json"
    good_proof = RAW / "cap50_low.proof"
    collector_cases: list[dict] = []

    v = write_verify_case("collector_legit", good_public, good_proof)
    collector_cases.append({
        "case": "legit_allowlist_collector", "accepted": v.get("accepted"),
        "reason": v.get("reason"), "layer": "all",
    })

    # forged public key: claimed key + attacker signature, legitimate collector_id
    forged_path = RAW / "collector_forged_key.public.json"
    forged = json.loads(good_public.read_text(encoding="utf-8"))
    raw_attacker = Ed25519PrivateKey.from_private_bytes(ATTACKER_SK).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    forged["collector_public_key_claimed"] = raw_attacker.hex()
    forged_path.write_text(json.dumps(forged, indent=2, ensure_ascii=False), encoding="utf-8")
    sign_public(forged_path, ATTACKER_SK)
    v = write_verify_case("collector_forged_key", forged_path, good_proof)
    collector_cases.append({
        "case": "forged_public_key", "accepted": v.get("accepted"),
        "reason": v.get("reason"), "layer": "allowlist+Ed25519 (claimed key ignored)",
    })

    # wrong collector_id: attacker id not in allowlist
    bad_id_path = RAW / "collector_wrong_id.public.json"
    bad_id = json.loads(good_public.read_text(encoding="utf-8"))
    bad_id["collector_id"] = collector_id(ATTACKER_SK)
    bad_id_path.write_text(json.dumps(bad_id, indent=2, ensure_ascii=False), encoding="utf-8")
    sign_public(bad_id_path, ATTACKER_SK)
    v = write_verify_case("collector_wrong_id", bad_id_path, good_proof)
    collector_cases.append({
        "case": "wrong_collector_id", "accepted": v.get("accepted"),
        "reason": v.get("reason"), "layer": "allowlist",
    })

    # wrong nonce: re-signed with the correct key, rejection must come from SNARK public input
    bad_nonce_path = RAW / "collector_wrong_nonce.public.json"
    bad_nonce = json.loads(good_public.read_text(encoding="utf-8"))
    bad_nonce["nonce"] += 1
    bad_nonce_path.write_text(json.dumps(bad_nonce, indent=2, ensure_ascii=False), encoding="utf-8")
    sign_public(bad_nonce_path, TEST_SK)
    v = write_verify_case("collector_wrong_nonce", bad_nonce_path, good_proof)
    collector_cases.append({
        "case": "wrong_nonce", "accepted": v.get("accepted"),
        "reason": v.get("reason"), "layer": "SNARK public input (Ed25519 re-signed)",
    })

    # wrong signature: legitimate id + legitimate allowlist key, tampered signature
    bad_sig_path = RAW / "collector_wrong_signature.public.json"
    bad_sig = json.loads(good_public.read_text(encoding="utf-8"))
    sig_bytes = bytearray(bytes.fromhex(bad_sig["collector_signature"]))
    sig_bytes[0] ^= 0x01
    bad_sig["collector_signature"] = sig_bytes.hex()
    bad_sig_path.write_text(json.dumps(bad_sig, indent=2, ensure_ascii=False), encoding="utf-8")
    v = write_verify_case("collector_wrong_signature", bad_sig_path, good_proof)
    collector_cases.append({
        "case": "wrong_signature", "accepted": v.get("accepted"),
        "reason": v.get("reason"), "layer": "Ed25519 signature",
    })

    (RAW / "collector_cases.json").write_text(
        json.dumps(collector_cases, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    summary = {
        "setup": setup,
        "perf": perf_rows,
        "proof_negatives": proof_negatives,
        "collector_cases": collector_cases,
    }
    (RAW / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps({
        "ok": True,
        "positives": [r["accepted"] for r in perf_rows],
        "negatives": [n["verify_accepted"] for n in proof_negatives],
        "collector": [c["accepted"] for c in collector_cases],
    }))


if __name__ == "__main__":
    main()
