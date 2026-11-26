#!/usr/bin/env python3
"""Phase 1B.1.2: cap=50 soundness audit and performance run.

Only cap=50 is executed.  Original Phase 1B/1B.1 raw data are never touched.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from run_phase1b1 import run_monitored

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "halo2" / "target" / "release" / "zk-agent-ifc-audit-halo2.exe"
RAW = ROOT / "experiments" / "phase1b1_2" / "raw"
ALLOWLIST = ROOT / "config" / "trusted_collectors.test.json"

CAP = 50
REUSE_ATTACK = "--reuse-attack" in sys.argv[1:]
DENSITIES = ["low", "mid", "high"]
SEEDS = {"low": 2026112601, "mid": 2026112602, "high": 2026112603}
NEG_CASES = [
    "illegal_ifc",
    "node_tl_mismatch",
    "edge_idx_mismatch",
    "crossbar_prev_dst",
]


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


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)

    setup_path = RAW / "setup50.json"
    print("[setup] cap=50", flush=True)
    setup_run = run_monitored([str(BIN), "setup", str(CAP), str(setup_path)])
    setup = json.loads(setup_path.read_text(encoding="utf-8"))
    setup["setup_wall_ms"] = setup_run["wall_ms"]
    setup["setup_peak_mb"] = setup_run["peak_mb"]
    setup_path.write_text(json.dumps(setup, indent=2, ensure_ascii=False), encoding="utf-8")

    selftest = run_monitored([str(BIN), "selftest", str(CAP)])
    selftest_data = last_json(selftest["stdout"])
    (RAW / "selftest50.json").write_text(
        json.dumps(selftest_data, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    attack_path = RAW / "post_fix_attacks.json"
    if REUSE_ATTACK and attack_path.exists():
        attack_data = json.loads(attack_path.read_text(encoding="utf-8"))
        print("[attack] reusing existing post-fix result", flush=True)
    else:
        attack_run = run_monitored([str(BIN), "attack", str(CAP)])
        attack_data = last_json(attack_run["stdout"])
        attack_path.write_text(
            json.dumps(attack_data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    perf_rows: list[dict] = []
    for density in DENSITIES:
        seed = SEEDS[density]
        proof_path = RAW / f"cap50_{density}.proof"
        public_path = RAW / f"cap50_{density}.public.json"
        meta_path = RAW / f"cap50_{density}.meta.json"
        verify_path = RAW / f"cap50_{density}.verify.json"
        print(f"  [prove] cap=50 density={density}", flush=True)
        prove_run = run_monitored([
            str(BIN), "prove", str(CAP), density, str(seed), str(setup_path),
            str(proof_path), str(public_path), str(meta_path),
        ])
        print(f"  [verify] cap=50 density={density}", flush=True)
        verify_run = run_monitored([
            str(BIN), "verify", str(setup_path), str(ALLOWLIST),
            str(proof_path), str(public_path), str(verify_path),
        ])
        public = json.loads(public_path.read_text(encoding="utf-8"))
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        verified = json.loads(verify_path.read_text(encoding="utf-8"))
        row = {
            "density": density, "active_edges": meta["active_edges"],
            "proof_bytes": public["proof_bytes"], "prove_ms": public["prove_ms"],
            "pure_verify_ms": verified.get("pure_verify_ms"),
            "vk_rebuild_ms": verified.get("vk_rebuild_ms"),
            "sig_verify_ms": verified.get("sig_verify_ms"),
            "params_gen_ms": setup["params_gen_ms"], "vk_gen_ms": setup["vk_gen_ms"],
            "pk_gen_ms": setup["pk_gen_ms"],
            "prove_wall_ms": prove_run["wall_ms"], "verify_wall_ms": verify_run["wall_ms"],
            "prove_peak_mb": prove_run["peak_mb"], "verify_peak_mb": verify_run["peak_mb"],
            "accepted": verified.get("accepted"),
        }
        perf_rows.append(row)
        (RAW / f"cap50_{density}.json").write_text(
            json.dumps(row, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    proof_negatives: list[dict] = []
    for case in NEG_CASES:
        proof_path = RAW / f"neg_{case}.proof"
        public_path = RAW / f"neg_{case}.public.json"
        verify_path = RAW / f"neg_{case}.verify.json"
        run = run_monitored([
            str(BIN), "prove-attack", str(CAP), case, str(setup_path),
            str(proof_path), str(public_path),
        ])
        prove_result = last_json(run["stdout"])
        accepted = None
        reason = prove_result.get("reason")
        if prove_result.get("create_proof_ok"):
            run2 = run_monitored([
                str(BIN), "verify", str(setup_path), str(ALLOWLIST),
                str(proof_path), str(public_path), str(verify_path),
            ])
            verified = json.loads(verify_path.read_text(encoding="utf-8"))
            accepted = verified.get("accepted")
            reason = verified.get("reason")
        proof_negatives.append({
            "case": case,
            "create_proof_ok": prove_result.get("create_proof_ok"),
            "verify_accepted": accepted,
            "reason": reason,
        })
    (RAW / "proof_layer_negatives.json").write_text(
        json.dumps(proof_negatives, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    good_public = RAW / "cap50_low.public.json"
    good_proof = RAW / "cap50_low.proof"
    collector_attacks: list[dict] = []
    test_sk = bytes([0x11] * 32)
    attacker_sk = bytes([0x22] * 32)

    # Wrong nonce: re-signed so the rejection comes from proof public-input binding.
    bad_nonce_path = RAW / "collector_wrong_nonce.public.json"
    bad_nonce_verify = RAW / "collector_wrong_nonce.verify.json"
    bad_nonce = json.loads(good_public.read_text(encoding="utf-8"))
    bad_nonce["nonce"] += 1
    bad_nonce_path.write_text(json.dumps(bad_nonce, indent=2, ensure_ascii=False), encoding="utf-8")
    sign_public(bad_nonce_path, test_sk)
    run_monitored([str(BIN), "verify", str(setup_path), str(ALLOWLIST),
        str(good_proof), str(bad_nonce_path), str(bad_nonce_verify)])
    v = json.loads(bad_nonce_verify.read_text(encoding="utf-8"))
    collector_attacks.append({"case": "wrong_nonce", "accepted": v.get("accepted"), "reason": v.get("reason")})

    # Forged key: claimed key and signature come from an untrusted key.
    forged_path = RAW / "collector_forged_key.public.json"
    forged_verify = RAW / "collector_forged_key.verify.json"
    forged = json.loads(good_public.read_text(encoding="utf-8"))
    forged_attacker = Ed25519PrivateKey.from_private_bytes(attacker_sk)
    raw_attacker = forged_attacker.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    forged["collector_public_key_claimed"] = raw_attacker.hex()
    forged_path.write_text(json.dumps(forged, indent=2, ensure_ascii=False), encoding="utf-8")
    sign_public(forged_path, attacker_sk)
    run_monitored([str(BIN), "verify", str(setup_path), str(ALLOWLIST),
        str(good_proof), str(forged_path), str(forged_verify)])
    v = json.loads(forged_verify.read_text(encoding="utf-8"))
    collector_attacks.append({"case": "forged_public_key", "accepted": v.get("accepted"), "reason": v.get("reason")})

    # Wrong collector_id: not present in allowlist.
    bad_id_path = RAW / "collector_wrong_id.public.json"
    bad_id_verify = RAW / "collector_wrong_id.verify.json"
    bad_id = json.loads(good_public.read_text(encoding="utf-8"))
    bad_id["collector_id"] = collector_id(attacker_sk)
    bad_id_path.write_text(json.dumps(bad_id, indent=2, ensure_ascii=False), encoding="utf-8")
    sign_public(bad_id_path, attacker_sk)
    run_monitored([str(BIN), "verify", str(setup_path), str(ALLOWLIST),
        str(good_proof), str(bad_id_path), str(bad_id_verify)])
    v = json.loads(bad_id_verify.read_text(encoding="utf-8"))
    collector_attacks.append({"case": "wrong_collector_id", "accepted": v.get("accepted"), "reason": v.get("reason")})

    (RAW / "collector_attacks.json").write_text(
        json.dumps(collector_attacks, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    lines = [
        "# Phase 1B.1.2 cap=50 实测结果",
        "",
        "仅运行 cap=50；Phase 1B / 1B.1 原始数据未改。",
        "verifier 只读取 setup、独立 allowlist、proof、public；不读取图或 witness。",
        "public.json 不含 blind、density、active_edges；这些字段只写入私有 meta.json。",
        "",
        "## Setup（一次性）",
        "",
        f"- k={setup['k']}，params={setup['params_gen_ms']} ms，vk={setup['vk_gen_ms']} ms，"
        f"pk={setup['pk_gen_ms']} ms，setup wall={setup['setup_wall_ms']} ms，"
        f"peak={setup['setup_peak_mb']} MB",
        "",
        "## Prove / Verify",
        "",
        "| density | active | proof_B | prove_ms | pure_verify_ms | vk_rebuild_ms | "
        "sig_verify_ms | prove_wall_ms | verify_wall_ms | prove_peak_MB | verify_peak_MB | accepted |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for r in perf_rows:
        lines.append(
            f"| {r['density']} | {r['active_edges']} | {r['proof_bytes']} | {r['prove_ms']} | "
            f"{r['pure_verify_ms']} | {r['vk_rebuild_ms']} | {r['sig_verify_ms']} | "
            f"{r['prove_wall_ms']} | {r['verify_wall_ms']} | {r['prove_peak_mb']} | "
            f"{r['verify_peak_mb']} | {r['accepted']} |"
        )
    lines += [
        "",
        "- `pure_verify_ms` 只含 `verify_proof`；`verify_wall_ms` 含 Params 生成、VK 重建、验签与文件读取。",
        "- `prove_ms` 只含 `create_proof`；`prove_wall_ms` 含进程启动、keygen 与 witness 生成。",
        "- 当前 prove 仍调用 `keygen_with_k()`，setup 时间不可视为已缓存复用。",
        "",
        "## 证明层负向测试",
        "",
        "| case | create_proof_ok | verify_accepted | reason |",
        "| --- | --- | --- | --- |",
    ]
    for r in proof_negatives:
        lines.append(f"| {r['case']} | {r['create_proof_ok']} | {r['verify_accepted']} | {r['reason']} |")
    lines += [
        "",
        "## 采集器身份负向测试",
        "",
        "| case | accepted | reason |",
        "| --- | --- | --- |",
    ]
    for r in collector_attacks:
        lines.append(f"| {r['case']} | {r['accepted']} | {r['reason']} |")
    lines += [
        "",
        "## 攻击套件（MockProver）",
        "",
        f"共 {len(attack_data['cases'])} 例；逐例结果见 `raw/post_fix_attacks.json`，修复前见 `raw/pre_fix_attacks.json`。",
        "",
    ]
    (ROOT / "experiments" / "phase1b1_2" / "RESULTS.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    print("\n".join(lines))


if __name__ == "__main__":
    main()
