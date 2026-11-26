"""Phase 1B.1.2 host-side acceptance tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ifc_audit.binding import collector_id_from_public_key_bytes
from ifc_audit.encoding import encode_graph_fixed
from ifc_audit.model import Graph, Label, Node, NodeType


ROOT = Path(__file__).resolve().parents[1]


def test_collector_id_rule_matches_rust_test_fixture() -> None:
    sk = Ed25519PrivateKey.from_private_bytes(bytes([0x11] * 32))
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert collector_id_from_public_key_bytes(raw) == 1205390390791845139

    allowlist = json.loads((ROOT / "config" / "trusted_collectors.test.json").read_text(
        encoding="utf-8"
    ))
    entry = allowlist["collectors"][0]
    assert entry["collector_public_key"] == raw.hex()
    assert entry["collector_id"] == collector_id_from_public_key_bytes(bytes.fromhex(
        entry["collector_public_key"]
    ))
    # SHA-256 prefix, not a truncated raw public key.
    assert collector_id_from_public_key_bytes(raw) == (
        int.from_bytes(hashlib.sha256(raw).digest()[:8], "big") & ((1 << 63) - 1)
    )


def test_graph_encoding_dict_does_not_expose_blind() -> None:
    graph = Graph(
        nodes=(Node(0, NodeType.PUBLIC_SOURCE, Label.LOW),), edges=()
    )
    enc = encode_graph_fixed(graph, max_events=2, edge_cap=4, blind=12345)
    exposed = enc.as_dict()
    assert "blind" not in exposed
    assert exposed["commitment"] == hex(enc.commitment)
