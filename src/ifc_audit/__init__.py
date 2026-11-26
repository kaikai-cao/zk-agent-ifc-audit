"""Phase 1A reference model for ZK-AGENT-IFC-AUDIT."""

from .model import (
    Edge,
    Graph,
    Label,
    Node,
    NodeType,
    build_forward_closure,
    check_forward_closure,
    reachable_high_to_low_sink,
    trace_ifc_compliant,
)

__all__ = [
    "Edge",
    "Graph",
    "Label",
    "Node",
    "NodeType",
    "build_forward_closure",
    "check_forward_closure",
    "reachable_high_to_low_sink",
    "trace_ifc_compliant",
]
