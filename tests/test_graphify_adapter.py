import hashlib
import json
from pathlib import Path

from bitmap_memory_portal.graphify_adapter import build_graphify_checkpoint
from test_cli import run_cli


def _write_graph(path: Path) -> None:
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "portal", "label": "portal.py", "_origin": "ast"},
                    {"id": "render", "label": "render", "_origin": "ast"},
                ],
                "edges": [
                    {
                        "source": "portal",
                        "target": "render",
                        "relation": "defines",
                        "confidence": "EXTRACTED",
                        "_origin": "ast",
                    },
                    {
                        "source": "render",
                        "target": "portal",
                        "relation": "supports",
                        "confidence": "INFERRED",
                        "_origin": "semantic",
                    },
                ],
                "hyperedges": [],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def test_build_graphify_checkpoint_records_derived_graph_boundary(tmp_path):
    graph_path = tmp_path / "graphify-out" / "graph.json"
    _write_graph(graph_path)

    checkpoint = build_graphify_checkpoint(
        graph_path=graph_path,
        source_path=tmp_path / "source",
        graphify_version="0.9.22",
        command=["graphify", "extract", "source", "--code-only", "--no-cluster"],
    )

    expected_hash = hashlib.sha256(graph_path.read_bytes()).hexdigest()
    assert checkpoint["checkpoint_type"] == "organa-derived-knowledge-graph"
    assert checkpoint["adapter_id"] == "graphify"
    assert checkpoint["adapter_version"] == "0.9.22"
    assert checkpoint["graph_sha256"] == f"sha256:{expected_hash}"
    assert checkpoint["node_count"] == 2
    assert checkpoint["edge_count"] == 2
    assert checkpoint["edge_confidence_counts"] == {"EXTRACTED": 1, "INFERRED": 1}
    assert checkpoint["edge_origin_counts"] == {"ast": 1, "semantic": 1}
    assert checkpoint["evidence_class"] == "derived"
    assert checkpoint["canonical_state_mutation"] is False
    assert checkpoint["approval_required_for_canonical_use"] is True
    assert Path(checkpoint["command"][0]).name == "graphify"
    assert checkpoint["command"][-2:] == ["--code-only", "--no-cluster"]


def test_cli_graphify_checkpoint_runs_code_only_extraction(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "sample.py").write_text(
        "def greet(name):\n    return f'hello {name}'\n",
        encoding="utf-8",
    )

    result = run_cli([
        "graphify-checkpoint",
        "--source", str(source),
        "--out", str(out),
    ])

    assert result.returncode == 0, result.stderr
    graph_path = out / "graphify-out" / "graph.json"
    checkpoint_path = out / "organa_graph_checkpoint.json"
    assert graph_path.exists()
    assert checkpoint_path.exists()

    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    assert checkpoint["node_count"] >= 2
    assert checkpoint["edge_count"] >= 1
    assert checkpoint["edge_confidence_counts"]["EXTRACTED"] >= 1
    assert checkpoint["canonical_state_mutation"] is False
    assert checkpoint["extraction_policy"] == {
        "code_only": True,
        "clustering": False,
        "semantic_documents": False,
        "multimedia": False,
    }
    payload = json.loads(result.stdout)
    assert payload["checkpoint_path"] == str(checkpoint_path)
    assert payload["graph_path"] == str(graph_path)
