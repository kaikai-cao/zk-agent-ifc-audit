"""Phase 1A acceptance tests A-G plus closure/BFS/DFS consistency.

These are ordinary-program tests.  They do not prove cryptographic soundness.
"""

from __future__ import annotations

import random
from dataclasses import replace

import pytest

from ifc_audit.binding import (
    BindingContext,
    collector_id_from_public_key,
    generate_collector_key,
    sign_attestation,
    verify_attestation,
)
from ifc_audit.encoding import (
    DOMAIN_BIND,
    DOMAIN_BLIND,
    FIELD_MODULUS,
    commit,
    encode_graph,
    encode_graph_fixed,
    poseidon_permutation_check,
)
from ifc_audit.model import (
    Edge,
    Graph,
    Label,
    Node,
    NodeType,
    build_forward_closure,
    check_forward_closure,
    reachable_high_to_low_sink,
    reachable_high_to_low_sink_dfs,
    trace_ifc_compliant,
)
from ifc_audit.poseidon import hash_const_len


def n(i: int, t: NodeType, lab: Label) -> Node:
    return Node(id=i, type=t, label=lab)


def assert_reference_consistent(graph: Graph, expected: bool) -> None:
    closure = build_forward_closure(graph)
    assert check_forward_closure(graph, closure) is expected
    assert trace_ifc_compliant(graph) is expected
    assert reachable_high_to_low_sink(graph) is (not expected)
    assert reachable_high_to_low_sink_dfs(graph) is (not expected)


# ---------------------------------------------------------------------------
# A. clean graph: accepted
# ---------------------------------------------------------------------------
def test_a_clean_graph_accepted() -> None:
    graph = Graph(
        nodes=(
            n(0, NodeType.CONFIDENTIAL_SOURCE, Label.HIGH),
            n(1, NodeType.TOOL_INVOCATION, Label.HIGH),
            n(2, NodeType.TOOL_RESULT, Label.HIGH),
            n(3, NodeType.PUBLIC_SOURCE, Label.LOW),
            n(4, NodeType.MODEL_OUTPUT, Label.LOW),
            n(5, NodeType.PUBLIC_SINK, Label.LOW),
        ),
        edges=(
            Edge(0, 1, 0),
            Edge(1, 2, 0),
            Edge(3, 4, 0),
            Edge(4, 5, 0),
        ),
    )
    assert_reference_consistent(graph, True)
    # The High chain and the Low egress chain are disconnected.
    assert build_forward_closure(graph) == frozenset({0, 1, 2})


# ---------------------------------------------------------------------------
# B. direct High -> Low edge: rejected
# ---------------------------------------------------------------------------
def test_b_direct_high_to_low_edge_rejected() -> None:
    graph = Graph(
        nodes=(
            n(0, NodeType.CONFIDENTIAL_SOURCE, Label.HIGH),
            n(1, NodeType.PUBLIC_SINK, Label.LOW),
        ),
        edges=(Edge(0, 1, 0),),
    )
    assert_reference_consistent(graph, False)


# ---------------------------------------------------------------------------
# C. multi-hop High -> Low path: rejected
# ---------------------------------------------------------------------------
def test_c_multihop_high_to_low_rejected() -> None:
    graph = Graph(
        nodes=(
            n(0, NodeType.CONFIDENTIAL_SOURCE, Label.HIGH),
            n(1, NodeType.TOOL_INVOCATION, Label.HIGH),
            n(2, NodeType.TOOL_RESULT, Label.HIGH),
            n(3, NodeType.MODEL_OUTPUT, Label.LOW),
            n(4, NodeType.PUBLIC_SINK, Label.LOW),
        ),
        edges=(
            Edge(0, 1, 0),
            Edge(1, 2, 1),  # control dependency in the middle
            Edge(2, 3, 0),
            Edge(3, 4, 0),
        ),
    )
    assert_reference_consistent(graph, False)
    # C2 propagates through all four edges; C3 forbids the sink in S.
    assert not check_forward_closure(graph, build_forward_closure(graph))


# ---------------------------------------------------------------------------
# D. omitted edge: forged clean graph is accepted; collector gap is invisible
# ---------------------------------------------------------------------------
def test_d_omitted_dangerous_edge_is_not_detected_by_graph_predicate() -> None:
    full = Graph(
        nodes=(
            n(0, NodeType.CONFIDENTIAL_SOURCE, Label.HIGH),
            n(1, NodeType.MODEL_OUTPUT, Label.LOW),
            n(2, NodeType.PUBLIC_SINK, Label.LOW),
        ),
        edges=(Edge(0, 1, 0), Edge(1, 2, 0)),
    )
    clean = Graph(nodes=full.nodes, edges=(Edge(0, 1, 0),))
    assert_reference_consistent(full, False)
    assert_reference_consistent(clean, True)
    # The proof relation would bind a different root for the two graphs.
    assert encode_graph(full).root != encode_graph(clean).root
    # This is precisely the trust-boundary gap: a valid proof for `clean`
    # says nothing about the missing edge in the actual execution.


# ---------------------------------------------------------------------------
# E. wrongly declassified label: relation cannot judge label truth
# ---------------------------------------------------------------------------
def test_e_wrongly_downgraded_label_is_not_detected() -> None:
    true_graph = Graph(
        nodes=(
            n(0, NodeType.CONFIDENTIAL_SOURCE, Label.HIGH),
            n(1, NodeType.PUBLIC_SINK, Label.LOW),
        ),
        edges=(Edge(0, 1, 0),),
    )
    mislabeled = Graph(
        nodes=(
            n(0, NodeType.CONFIDENTIAL_SOURCE, Label.LOW),
            n(1, NodeType.PUBLIC_SINK, Label.LOW),
        ),
        edges=true_graph.edges,
    )
    assert_reference_consistent(true_graph, False)
    assert_reference_consistent(mislabeled, True)
    # Label authenticity belongs to the collector/policy authority.


# ---------------------------------------------------------------------------
# F. nonce / session mismatch: rejected at verification/binding layer
# ---------------------------------------------------------------------------
def test_f_nonce_and_session_mismatch_rejected() -> None:
    key = generate_collector_key()
    cid = collector_id_from_public_key(key.public_key())
    ctx = BindingContext(
        commitment=12345,
        policy_id=7,
        session_id=20261126,
        nonce=99,
        collector_id=cid,
    )
    sig = sign_attestation(key, ctx)
    assert verify_attestation(key.public_key(), ctx, sig)

    bad_nonce = replace(ctx, nonce=100)
    bad_session = replace(ctx, session_id=20261127)
    assert not verify_attestation(key.public_key(), bad_nonce, sig)
    assert not verify_attestation(key.public_key(), bad_session, sig)
    assert ctx.binding_hash() != bad_nonce.binding_hash()
    assert ctx.binding_hash() != bad_session.binding_hash()
    # Domain separation value is a fixed Poseidon ConstantLength input.
    assert ctx.binding_hash() == hash_const_len(
        [DOMAIN_BIND, ctx.commitment, ctx.policy_id, ctx.session_id, ctx.nonce]
    )


# ---------------------------------------------------------------------------
# G. inconsistent node/edge/label encoding: rejected via root mismatch
# ---------------------------------------------------------------------------
def test_g_inconsistent_encoding_rejected() -> None:
    graph = Graph(
        nodes=(
            n(0, NodeType.CONFIDENTIAL_SOURCE, Label.HIGH),
            n(1, NodeType.PUBLIC_SINK, Label.LOW),
        ),
        edges=(Edge(0, 1, 0),),
    )
    enc = encode_graph(graph)

    # Change the label of node 0 without changing the committed root.
    tampered = Graph(
        nodes=(n(0, NodeType.CONFIDENTIAL_SOURCE, Label.LOW), graph.nodes[1]),
        edges=graph.edges,
    )
    assert encode_graph(tampered).root != enc.root

    # Change an edge kind without changing the committed root.
    changed_edge = Graph(
        nodes=graph.nodes,
        edges=(Edge(0, 1, 1),),
    )
    assert encode_graph(changed_edge).root != enc.root

    # Add an inconsistent edge and recompute the root; the old root cannot bind it.
    extra_edge = Graph(nodes=graph.nodes, edges=(Edge(0, 1, 0), Edge(1, 0, 0)))
    assert encode_graph(extra_edge).root != enc.root
    assert reachable_high_to_low_sink(extra_edge)


# ---------------------------------------------------------------------------
# Structural and cross-check tests
# ---------------------------------------------------------------------------
def test_poseidon_permutation_matches_official_vector() -> None:
    assert poseidon_permutation_check()


def test_invalid_graph_encodings_are_rejected() -> None:
    with pytest.raises(ValueError):
        Graph(nodes=(n(0, NodeType.PUBLIC_SINK, Label.LOW),), edges=(Edge(0, 9, 0),))
    with pytest.raises(ValueError):
        Graph(nodes=(n(0, NodeType.PUBLIC_SINK, Label.LOW),), edges=(Edge(0, 0, 0),))
    with pytest.raises(ValueError):
        Edge(0, 1, 2)
    with pytest.raises(ValueError):
        Graph(
            nodes=(n(0, NodeType.PUBLIC_SINK, Label.LOW),), edges=()
        ).validate(max_events=0)


def test_closure_equals_bfs_dfs_on_random_small_graphs() -> None:
    rng = random.Random(38202611)
    for _ in range(120):
        size = rng.randint(2, 9)
        nodes = []
        for i in range(size):
            node_type = NodeType(rng.randrange(len(NodeType)))
            label = Label(rng.randrange(2))
            if node_type == NodeType.CONFIDENTIAL_SOURCE:
                label = Label.HIGH
            if node_type == NodeType.PUBLIC_SOURCE:
                label = Label.LOW
            nodes.append(n(i, node_type, label))
        edges = []
        for i in range(size):
            for j in range(size):
                if i != j and rng.random() < 0.18:
                    edges.append(Edge(i, j, rng.randrange(2)))
        graph = Graph(nodes=tuple(nodes), edges=tuple(edges))
        closure = build_forward_closure(graph)
        by_closure = check_forward_closure(graph, closure)
        assert reachable_high_to_low_sink(graph) is (not by_closure)
        assert reachable_high_to_low_sink_dfs(graph) is (not by_closure)
        assert trace_ifc_compliant(graph) is by_closure


# ---------------------------------------------------------------------------
# Phase 1B.1: randomized commitment (hiding vs binding)
# ---------------------------------------------------------------------------
def _blind_graph() -> Graph:
    return Graph(
        nodes=(
            n(0, NodeType.CONFIDENTIAL_SOURCE, Label.HIGH),
            n(1, NodeType.PUBLIC_SINK, Label.LOW),
        ),
        edges=(),
    )


def test_commitment_hides_graph_against_enumeration() -> None:
    graph = _blind_graph()
    first = encode_graph_fixed(graph, max_events=4, edge_cap=8, blind=12345)
    second = encode_graph_fixed(graph, max_events=4, edge_cap=8, blind=67890)
    assert first.root == second.root, "blinding must not change the binding root"
    assert first.commitment != second.commitment, "different blind must hide linkage"
    assert first.commitment == commit(first.root, 12345, 4)
    assert first.blind == 12345


def test_commitment_rejects_graph_or_blind_substitution() -> None:
    graph = _blind_graph()
    original = encode_graph_fixed(graph, max_events=4, edge_cap=8, blind=12345)
    changed = Graph(
        nodes=graph.nodes,
        edges=(Edge(0, 1, 0),),
    )
    remapped = encode_graph_fixed(changed, max_events=4, edge_cap=8, blind=12345)
    assert remapped.commitment != original.commitment
    reblinded = encode_graph_fixed(graph, max_events=4, edge_cap=8, blind=12346)
    assert reblinded.commitment != original.commitment


def test_commitment_blind_must_be_canonical_field_element() -> None:
    graph = _blind_graph()
    with pytest.raises(ValueError):
        encode_graph_fixed(graph, max_events=4, edge_cap=8, blind=FIELD_MODULUS)
    with pytest.raises(ValueError):
        commit(0, -1, 4)
    assert DOMAIN_BLIND != DOMAIN_BIND
