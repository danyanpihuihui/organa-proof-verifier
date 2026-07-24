from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List


def build_citation_graph(citations_files: Iterable[Path]) -> Dict:
    nodes = {}
    edges = []
    for p in citations_files:
        data = json.loads(Path(p).read_text(encoding='utf-8'))
        src = data.get('source_bitmap')
        if src:
            nodes.setdefault(src, {'bitmap': src})
        for item in data.get('citations') or []:
            tgt = item.get('target_bitmap')
            if tgt:
                nodes.setdefault(tgt, {'bitmap': tgt})
            edges.append({
                'source': src,
                'target': tgt,
                'relation': item.get('relation'),
                'weight': item.get('weight'),
                'verification_status': item.get('verification_status'),
                'note': item.get('note'),
                'evidence': item.get('evidence'),
            })
    indeg = defaultdict(int)
    outdeg = defaultdict(int)
    for e in edges:
        if e.get('source'):
            outdeg[e['source']] += 1
        if e.get('target'):
            indeg[e['target']] += 1
    for b in nodes:
        nodes[b]['incoming'] = indeg[b]
        nodes[b]['outgoing'] = outdeg[b]
    return {'schema_version': '0.1.0', 'nodes': list(nodes.values()), 'edges': edges, 'node_count': len(nodes), 'edge_count': len(edges)}
