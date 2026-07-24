from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _count_field(rows: Iterable[Dict], field: str, default: str = "UNKNOWN") -> Dict[str, int]:
    counts = Counter(str(row.get(field) or default) for row in rows)
    return dict(sorted(counts.items()))


def build_graphify_checkpoint(
    graph_path: Path,
    source_path: Path,
    graphify_version: str,
    command: Iterable[str],
) -> Dict:
    """Build an Organa checkpoint for a Graphify graph as derived evidence."""
    graph_path = Path(graph_path).expanduser().resolve()
    source_path = Path(source_path).expanduser().resolve()
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    return {
        "checkpoint_type": "organa-derived-knowledge-graph",
        "adapter_id": "graphify",
        "adapter_version": graphify_version,
        "source_path": str(source_path),
        "graph_path": str(graph_path),
        "graph_sha256": f"sha256:{_sha256_file(graph_path)}",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "hyperedge_count": len(graph.get("hyperedges") or []),
        "edge_confidence_counts": _count_field(edges, "confidence"),
        "edge_origin_counts": _count_field(edges, "_origin"),
        "command": list(command),
        "extraction_policy": {
            "code_only": True,
            "clustering": False,
            "semantic_documents": False,
            "multimedia": False,
        },
        "evidence_class": "derived",
        "canonical_state_mutation": False,
        "approval_required_for_canonical_use": True,
        "trust_boundary": (
            "Graphify output may describe source relationships, but it is not canonical "
            "Organa state until separately reviewed and approved."
        ),
    }
