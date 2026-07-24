from __future__ import annotations

import html
import json
from typing import Dict


def _esc(value) -> str:
    return html.escape('' if value is None else str(value))


def render_graph_html(graph: Dict) -> str:
    node_rows = ''.join(
        f"<tr><td>{_esc(n.get('bitmap'))}</td><td>{_esc(n.get('incoming'))}</td><td>{_esc(n.get('outgoing'))}</td></tr>"
        for n in graph.get('nodes', [])
    )
    edge_rows = ''.join(
        f"<tr><td>{_esc(e.get('source'))}</td><td>→</td><td>{_esc(e.get('target'))}</td><td>{_esc(e.get('relation'))}</td><td>{_esc(e.get('weight'))}</td><td>{_esc(e.get('verification_status'))}</td><td>{_esc(e.get('note'))}</td></tr>"
        for e in graph.get('edges', [])
    )
    graph_json = json.dumps(graph, ensure_ascii=False, indent=2)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Bitmap Citation Graph</title>
  <style>
    :root {{ color-scheme: dark; --bg:#050816; --panel:#0f172a; --line:#253047; --text:#e5e7eb; --muted:#94a3b8; --blue:#60a5fa; --green:#22c55e; }}
    body {{ margin:0; background:radial-gradient(circle at top left,#172554 0,#050816 38%,#020617 100%); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif; }}
    .wrap {{ max-width:1180px; margin:0 auto; padding:36px 20px 60px; }}
    .hero, section {{ border:1px solid var(--line); background:rgba(15,23,42,.82); border-radius:24px; padding:24px; margin-bottom:20px; }}
    .eyebrow {{ color:var(--blue); font-weight:800; letter-spacing:.08em; text-transform:uppercase; font-size:12px; }}
    h1 {{ margin:10px 0; font-size:42px; }}
    .desc {{ color:var(--muted); line-height:1.7; }}
    .grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }}
    .card {{ background:#07111f; border:1px solid var(--line); border-radius:16px; padding:16px; }}
    .label {{ color:var(--muted); font-size:12px; margin-bottom:8px; }}
    .value {{ font-size:28px; font-weight:900; }}
    table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
    th, td {{ border-bottom:1px solid rgba(148,163,184,.16); padding:11px 8px; text-align:left; vertical-align:top; }}
    th {{ color:#bfdbfe; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
    td {{ color:#e5e7eb; }}
    code, pre {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
    pre {{ white-space:pre-wrap; overflow:auto; max-height:460px; background:#020617; border:1px solid #1e293b; border-radius:16px; padding:16px; color:#d1d5db; font-size:12px; }}
    @media(max-width:860px) {{ .grid{{grid-template-columns:1fr}} table{{font-size:12px}} }}
  </style>
</head>
<body>
  <main class="wrap">
    <div class="hero">
      <div class="eyebrow">Bitmap-native trust graph</div>
      <h1>Bitmap Citation Graph</h1>
      <p class="desc">A graph view for Bitmap-to-Bitmap references. Incoming citations are structural confirmations; outgoing citations show which Bitmaps this coordinate references.</p>
      <div class="grid">
        <div class="card"><div class="label">Nodes</div><div class="value">{_esc(graph.get('node_count'))}</div></div>
        <div class="card"><div class="label">Edges</div><div class="value">{_esc(graph.get('edge_count'))}</div></div>
      </div>
    </div>
    <section>
      <h2>Nodes</h2>
      <table><thead><tr><th>Bitmap</th><th>Incoming</th><th>Outgoing</th></tr></thead><tbody>{node_rows}</tbody></table>
    </section>
    <section>
      <h2>Citation Edges</h2>
      <table><thead><tr><th>Source</th><th></th><th>Target</th><th>Relation</th><th>Weight</th><th>Status</th><th>Note</th></tr></thead><tbody>{edge_rows}</tbody></table>
    </section>
    <section>
      <h2>Raw graph.json</h2>
      <pre>{_esc(graph_json)}</pre>
    </section>
  </main>
</body>
</html>
"""
