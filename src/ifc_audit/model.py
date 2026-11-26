"""Plain-Python reference model for single-session Trace-IFC compliance.

This is an ordinary program.  It is NOT a proof and NOT a cryptographic claim.
See docs/PROBLEM_DEFINITION.md for the four distinct propositions.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable


class Label(IntEnum):
    LOW = 0
    HIGH = 1


class NodeType(IntEnum):
    CONFIDENTIAL_SOURCE = 0
    PUBLIC_SOURCE = 1
    MODEL_OUTPUT = 2
    TOOL_INVOCATION = 3
    TOOL_RESULT = 4
    PUBLIC_SINK = 5


@dataclass(frozen=True)
class Node:
    id: int
    type: NodeType
    label: Label


@dataclass(frozen=True)
class Edge:
    src: int
    dst: int
    kind: int  # 0 = data, 1 = control

    def __post_init__(self) -> None:
        if self.kind not in (0, 1):
            raise ValueError(f"unknown dependency kind: {self.kind}")


@dataclass(frozen=True)
class Graph:
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]

    def __post_init__(self) -> None:
        self.validate()

    @property
    def n(self) -> int:
        return len(self.nodes)

    @property
    def m(self) -> int:
        return len(self.edges)

    def index_map(self) -> dict[int, int]:
        return {node.id: pos for pos, node in enumerate(self.nodes)}

    def adjacency(self) -> dict[int, list[int]]:
        idx = self.index_map()
        adj: dict[int, list[int]] = {i: [] for i in range(self.n)}
        for e in self.edges:
            adj[idx[e.src]].append(idx[e.dst])
        return adj

    def validate(self, max_events: int | None = None) -> None:
        if not self.nodes:
            raise ValueError("graph must have at least one node")
        ids = [node.id for node in self.nodes]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate node id")
        if any(i < 0 for i in ids):
            raise ValueError("negative node id")
        idx = set(ids)
        for e in self.edges:
            if e.src not in idx or e.dst not in idx:
                raise ValueError(f"edge references unknown node: {e}")
            if e.src == e.dst:
                raise ValueError(f"self loop is not allowed: {e}")
        if max_events is not None and self.n > max_events:
            raise ValueError(f"node count {self.n} exceeds max_events {max_events}")
        for node in self.nodes:
            if not isinstance(node.type, NodeType):
                raise ValueError(f"unknown node type at {node.id}")
            if not isinstance(node.label, Label):
                raise ValueError(f"unknown label at {node.id}")


def reachable_high_to_low_sink(graph: Graph) -> bool:
    """Naive BFS over G.  True iff some High node reaches a Low public sink."""
    graph.validate()
    adj = graph.adjacency()
    low_sinks = {
        i
        for i, node in enumerate(graph.nodes)
        if node.type == NodeType.PUBLIC_SINK and node.label == Label.LOW
    }
    if not low_sinks:
        return False
    seen: set[int] = set()
    queue: deque[int] = deque()
    for i, node in enumerate(graph.nodes):
        if node.label == Label.HIGH:
            seen.add(i)
            queue.append(i)
    while queue:
        u = queue.popleft()
        if u in low_sinks:
            return True
        for v in adj[u]:
            if v not in seen:
                seen.add(v)
                queue.append(v)
    return False


def reachable_high_to_low_sink_dfs(graph: Graph) -> bool:
    """Second independent path search (DFS) used as a cross-check."""
    graph.validate()
    adj = graph.adjacency()
    low_sinks = {
        i
        for i, node in enumerate(graph.nodes)
        if node.type == NodeType.PUBLIC_SINK and node.label == Label.LOW
    }
    seen: set[int] = set()
    stack: list[int] = [
        i for i, node in enumerate(graph.nodes) if node.label == Label.HIGH
    ]
    while stack:
        u = stack.pop()
        if u in seen:
            continue
        if u in low_sinks:
            return True
        seen.add(u)
        stack.extend(adj[u])
    return False


def build_forward_closure(graph: Graph) -> frozenset[int]:
    """Smallest forward-closed set containing every High-labelled node."""
    graph.validate()
    adj = graph.adjacency()
    seen: set[int] = {
        i for i, node in enumerate(graph.nodes) if node.label == Label.HIGH
    }
    queue: deque[int] = deque(seen)
    while queue:
        u = queue.popleft()
        for v in adj[u]:
            if v not in seen:
                seen.add(v)
                queue.append(v)
    return frozenset(seen)


def check_forward_closure(graph: Graph, s: Iterable[int]) -> bool:
    """Check C1-C4 from docs/TRACE_IFC_RELATION.md on positional indices."""
    graph.validate()
    s_set = set(int(i) for i in s)
    if any(i < 0 or i >= graph.n for i in s_set):
        return False
    for i, node in enumerate(graph.nodes):
        if node.label == Label.HIGH and i not in s_set:
            return False
        if node.type == NodeType.PUBLIC_SINK and node.label == Label.LOW and i in s_set:
            return False
    idx = graph.index_map()
    for e in graph.edges:
        if idx[e.src] in s_set and idx[e.dst] not in s_set:
            return False
    return True


def trace_ifc_compliant(graph: Graph) -> bool:
    """Reference decision: exists a valid forward-closed set S."""
    return check_forward_closure(graph, build_forward_closure(graph))
