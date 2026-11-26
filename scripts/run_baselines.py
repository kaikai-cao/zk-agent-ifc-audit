#!/usr/bin/env python3
"""Plaintext checker / commitment+signature baselines and comparison with Halo2."""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

from ifc_audit.binding import (
    BindingContext,
    collector_id_from_public_key,
    generate_collector_key,
    sign_attestation,
    verify_attestation,
)
from ifc_audit.encoding import encode_graph_fixed
from ifc_audit.model import Edge, Graph, Label, Node, NodeType, trace_ifc_compliant

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "baselines"


def make_graph(cap: int, density: str, seed: int) -> Graph:
    rng = random.Random(seed)
    high_count = cap // 2
    nodes = []
    for i in range(cap):
        if i == cap - 1:
            nodes.append(Node(i, NodeType.PUBLIC_SINK, Label.LOW))
        elif i < high_count:
            typ = [NodeType.CONFIDENTIAL_SOURCE, NodeType.TOOL_INVOCATION, NodeType.TOOL_RESULT][i % 3]
            nodes.append(Node(i, typ, Label.HIGH))
        else:
            typ = NodeType.PUBLIC_SOURCE if i % 4 == 0 else NodeType.MODEL_OUTPUT
            nodes.append(Node(i, typ, Label.LOW))
    target = {"low": cap // 2, "mid": cap, "high": 2 * cap}[density]
    edges = []
    for count, lo, hi in [(target // 2, 0, high_count), (target - target // 2, high_count, cap)]:
        made = 0
        guard = 0
        while made < count and guard < 20000:
            guard += 1
            src = rng.randrange(lo, hi)
            dst = rng.randrange(lo, hi)
            if src == dst or any(e.src == src and e.dst == dst for e in edges):
                continue
            edges.append(Edge(src, dst, rng.randrange(2)))
            made += 1
        assert made == count
    return Graph(tuple(nodes), tuple(edges))


def measure(fn, repeats: int = 20) -> float:
    start = time.perf_counter()
    for _ in range(repeats):
        fn()
    return (time.perf_counter() - start) * 1000 / repeats


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    key = generate_collector_key()
    cid = collector_id_from_public_key(key.public_key())
    rows = []
    for cap in (50, 100, 200):
        for density in ("low", "mid", "high"):
            graph = make_graph(cap, density, 2026112600 + cap + len(density))
            enc = encode_graph_fixed(graph, cap, 2 * cap)
            ctx = BindingContext(enc.root, 7, 20261126, 1, cid)
            sig = sign_attestation(key, ctx)
            plaintext_ms = measure(lambda: trace_ifc_compliant(graph))
            sign_ms = measure(lambda: sign_attestation(key, ctx))
            verify_ms = measure(lambda: verify_attestation(key.public_key(), ctx, sig))
            verify_with_graph_ms = measure(
                lambda: (verify_attestation(key.public_key(), ctx, sig) and trace_ifc_compliant(graph))
            )
            rows.append(
                {
                    "cap": cap,
                    "density": density,
                    "edges": graph.m,
                    "plaintext_checker_ms": round(plaintext_ms, 6),
                    "collector_sign_ms": round(sign_ms, 6),
                    "signature_verify_ms": round(verify_ms, 6),
                    "signature_plus_plaintext_recompute_ms": round(verify_with_graph_ms, 6),
                    "root": hex(enc.root),
                }
            )

    halo2 = {}
    raw_dir = ROOT / "experiments" / "phase1b" / "raw"
    if raw_dir.exists():
        for path in raw_dir.glob("cap*_*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            halo2[(data["cap"], data["density"])] = data

    for r in rows:
        h = halo2.get((r["cap"], r["density"]))
        r["halo2_prove_ms"] = h["prove_ms"] if h else None
        r["halo2_verify_ms"] = h["verify_ms"] if h else None
        r["halo2_proof_bytes"] = h["proof_bytes"] if h else None
        r["prove_over_plaintext"] = (
            round(h["prove_ms"] / r["plaintext_checker_ms"], 1) if h else None
        )

    (OUT / "RESULTS.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    lines = [
        "# 基线对照实测",
        "",
        "所有时间为 Python 侧 20 次重复的中位近似（报告为均值毫秒）；Halo2 数值来自 `experiments/phase1b/raw/`。",
        "",
        "| cap | density | edges | plaintext ms | sign ms | verify ms | sig+recompute ms | Halo2 prove ms | Halo2 verify ms | proof B | prove/plaintext |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        lines.append(
            f"| {r['cap']} | {r['density']} | {r['edges']} | {r['plaintext_checker_ms']} | "
            f"{r['collector_sign_ms']} | {r['signature_verify_ms']} | "
            f"{r['signature_plus_plaintext_recompute_ms']} | {r['halo2_prove_ms']} | "
            f"{r['halo2_verify_ms']} | {r['halo2_proof_bytes']} | {r['prove_over_plaintext']} |"
        )
    lines += [
        "",
        "## 解释边界",
        "",
        "- Plaintext checker：验证者拿到完整图，直接跑 BFS/DFS；最快，但零隐私。",
        "- Commitment + signature：验证者验签；若要自行确认合规，仍须拿到图并重算谓词。",
        "- Halo2：验证者看不到图，只验证公开输入上的证明；成本显著更高，但不减少采集器完整性信任。",
        "- 表中倍率只反映本机这类合成图与实现，不宣称普遍性能优劣。",
    ]
    (OUT / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
