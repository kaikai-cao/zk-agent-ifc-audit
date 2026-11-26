"""Canonical fixed-capacity graph encoding and Poseidon Merkle commitment.

This is the host reference for the Phase 1B circuit.  The same domain tags,
leaf widths and Merkle shape are implemented in `halo2/src/main.rs`.

Encoding (all Poseidon P128Pow5T3, width 3 / rate 2):
  node_leaf(i) = H<3>(DOMAIN_NODE + cap, type_i*2 + label_i, i)
  edge_leaf(j) = H<3>(DOMAIN_EDGE + cap, src_j*cap + dst_j, kind_j)
  empty_leaf   = H<2>(DOMAIN_EMPTY + cap, 0)
  merge(a,b)   = H<2>(a, b)

`cap` is MAX_NODES.  Nodes are padded to `max_events` with PUBLIC_SOURCE /
LOW / S=0; edges are padded to `max_edges` with EMPTY leaves.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Graph, Label, Node, NodeType
from .poseidon import hash_const_len, permute

DOMAIN_NODE = 0x4E4F4445
DOMAIN_EDGE = 0x45444745
DOMAIN_EMPTY = 0x454D5054
DOMAIN_MERGE = 0x4D455247
DOMAIN_BIND = 0x42494E44


@dataclass(frozen=True)
class GraphEncoding:
    node_leaves: tuple[int, ...]
    edge_leaves: tuple[int, ...]
    depth: int
    root: int
    leaf_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "node_leaves": [hex(x) for x in self.node_leaves],
            "edge_leaves": [hex(x) for x in self.edge_leaves],
            "depth": self.depth,
            "leaf_count": self.leaf_count,
            "root": hex(self.root),
        }


def node_leaf(node: Node, position: int, cap: int) -> int:
    return hash_const_len(
        [DOMAIN_NODE + cap, int(node.type) * 2 + int(node.label), position]
    )


def edge_leaf(src: int, dst: int, kind: int, cap: int) -> int:
    return hash_const_len([DOMAIN_EDGE + cap, src * cap + dst, kind])


def empty_leaf(cap: int) -> int:
    return hash_const_len([DOMAIN_EMPTY + cap, 0])


def merge(left: int, right: int) -> int:
    return hash_const_len([left, right])


def merkle_root(leaves: list[int], cap: int) -> tuple[int, int]:
    if not leaves:
        leaves = [empty_leaf(cap)]
    layer = list(leaves)
    depth = 0
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(empty_leaf(cap))
        layer = [merge(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        depth += 1
    return layer[0], depth


def encode_graph_fixed(graph: Graph, max_events: int, edge_cap: int | None = None) -> GraphEncoding:
    """Fixed-capacity encoding used by the circuit."""
    graph.validate(max_events)
    if edge_cap is None:
        edge_cap = 2 * max_events
    nodes = list(graph.nodes)
    while len(nodes) < max_events:
        nodes.append(Node(len(nodes), NodeType.PUBLIC_SOURCE, Label.LOW))
    node_leaves = tuple(node_leaf(node, i, max_events) for i, node in enumerate(nodes))
    edge_leaves_list = [edge_leaf(e.src, e.dst, e.kind, max_events) for e in graph.edges]
    if len(edge_leaves_list) > edge_cap:
        raise ValueError(f"edge count {len(edge_leaves_list)} exceeds cap {edge_cap}")
    while len(edge_leaves_list) < edge_cap:
        edge_leaves_list.append(empty_leaf(max_events))
    edge_leaves = tuple(edge_leaves_list)
    leaves = list(node_leaves) + list(edge_leaves)
    root, depth = merkle_root(leaves, max_events)
    return GraphEncoding(node_leaves, edge_leaves, depth, root, len(leaves))


def encode_graph(graph: Graph, max_events: int | None = None) -> GraphEncoding:
    """Backwards-compatible variable-size encoding (Phase 1A tests only)."""
    graph.validate(max_events)
    node_leaves = tuple(node_leaf(node, i, graph.n) for i, node in enumerate(graph.nodes))
    edge_leaves = tuple(edge_leaf(e.src, e.dst, e.kind, graph.n) for e in graph.edges)
    leaves = list(node_leaves) + list(edge_leaves)
    root, depth = merkle_root(leaves, graph.n)
    return GraphEncoding(node_leaves, edge_leaves, depth, root, len(leaves))


def poseidon_permutation_check() -> bool:
    """Canonical vector from halo2_poseidon 0.2.0 test_vectors::fp::permute()[0]."""
    out = permute((0, 1, 2))
    expected = (
        0x2A526ACD0B64B45394EFB364F966240FF7E69A71D0B642A0AEB1BC024AECA456,
        0x13C5D1568B4AA43076FF7DAE343D5512DCD42E7FBED9DAFE012A3E9628E5B82A,
        0xA49C868C6976544256FCD597984561AF7CFDFE1BDA42C7B359029A1D34E9DDD,
    )
    return out == expected
