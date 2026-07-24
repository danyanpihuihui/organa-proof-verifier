import json
from pathlib import Path

from bitmap_memory_portal.graph import build_citation_graph
from bitmap_memory_portal.graph_render import render_graph_html


def test_build_citation_graph_counts_incoming_and_outgoing(tmp_path):
    a = tmp_path / 'a.json'
    b = tmp_path / 'b.json'
    a.write_text(json.dumps({
        'source_bitmap': '7187.bitmap',
        'citations': [{'target_bitmap': '0.bitmap', 'relation': 'conceptual-anchor', 'weight': 'strong', 'verification_status': 'declared', 'note': 'n1', 'evidence': 'e1'}]
    }), encoding='utf-8')
    b.write_text(json.dumps({
        'source_bitmap': '0.bitmap',
        'citations': [{'target_bitmap': '7187.bitmap', 'relation': 'reply', 'weight': 'medium', 'verification_status': 'declared', 'note': 'n2', 'evidence': 'e2'}]
    }), encoding='utf-8')

    graph = build_citation_graph([a, b])

    assert graph['node_count'] == 2
    assert graph['edge_count'] == 2
    nodes = {n['bitmap']: n for n in graph['nodes']}
    assert nodes['7187.bitmap']['outgoing'] == 1
    assert nodes['7187.bitmap']['incoming'] == 1
    html = render_graph_html(graph)
    assert 'Bitmap Citation Graph' in html
    assert '0.bitmap' in html
    assert 'conceptual-anchor' in html
