from __future__ import annotations

import html


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _short(value: str, n: int = 14) -> str:
    value = str(value or "")
    if len(value) <= n * 2 + 3:
        return value
    return value[:n] + "..." + value[-n:]


def render_landing_html(
    demo_portal_path: str,
    demo_manifest_hash: str,
    demo_merkle_root: str,
    demo_files_count: int,
    agent_name: str = "Bitmap Memory Guardian",
    demo_agent_root_type: str = "bitmap-agent-root",
    demo_skills_count: int = 0,
) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Bitmap Memory Portal</title>
  <style>
    :root {{ color-scheme: dark; --bg:#030712; --panel:#0f172a; --text:#f8fafc; --muted:#94a3b8; --line:#263449; --blue:#60a5fa; --green:#22c55e; --amber:#f59e0b; --purple:#a78bfa; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:radial-gradient(circle at 18% 0%,rgba(96,165,250,.22),transparent 32%),radial-gradient(circle at 80% 4%,rgba(167,139,250,.22),transparent 28%),#020617; color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif; }}
    .wrap {{ max-width:1200px; margin:0 auto; padding:42px 22px 70px; }}
    .nav {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:52px; color:#cbd5e1; }}
    .brand {{ display:flex; align-items:center; gap:10px; font-weight:900; }}
    .logo {{ width:34px; height:34px; border-radius:10px; background:linear-gradient(135deg,var(--blue),var(--purple)); box-shadow:0 0 36px rgba(96,165,250,.4); }}
    .hero {{ display:grid; grid-template-columns:1.08fr .92fr; gap:28px; align-items:center; }}
    .eyebrow {{ color:#93c5fd; text-transform:uppercase; letter-spacing:.12em; font-weight:900; font-size:12px; }}
    h1 {{ font-size:62px; line-height:.98; margin:14px 0 18px; letter-spacing:-.055em; }}
    .subtitle {{ font-size:22px; color:#dbeafe; line-height:1.45; margin:0 0 22px; }}
    .body {{ color:var(--muted); line-height:1.75; font-size:16px; max-width:680px; }}
    .cta-row {{ display:flex; gap:12px; flex-wrap:wrap; margin-top:28px; }}
    .btn {{ padding:13px 18px; border-radius:999px; font-weight:900; text-decoration:none; display:inline-flex; border:1px solid rgba(96,165,250,.36); }}
    .btn.primary {{ color:#020617; background:#93c5fd; }}
    .btn.secondary {{ color:#bfdbfe; background:rgba(15,23,42,.65); }}
    .demo-card {{ background:linear-gradient(180deg,rgba(15,23,42,.92),rgba(2,6,23,.92)); border:1px solid rgba(148,163,184,.22); border-radius:28px; padding:22px; box-shadow:0 30px 90px rgba(0,0,0,.38); }}
    .metric-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:16px 0; }}
    .metric {{ background:rgba(15,23,42,.85); border:1px solid var(--line); border-radius:18px; padding:15px; }}
    .metric span {{ color:var(--muted); font-size:12px; display:block; margin-bottom:8px; }}
    .metric b {{ color:#f8fafc; font-size:19px; word-break:break-all; }}
    .hash {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:#bbf7d0; font-size:12px; background:#06131f; border:1px solid rgba(34,197,94,.28); border-radius:14px; padding:12px; word-break:break-all; }}
    section {{ margin-top:28px; background:rgba(15,23,42,.72); border:1px solid rgba(148,163,184,.18); border-radius:26px; padding:26px; }}
    h2 {{ margin:0 0 18px; font-size:30px; letter-spacing:-.03em; }}
    .feature-grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; }}
    .feature {{ background:rgba(2,6,23,.55); border:1px solid var(--line); border-radius:20px; padding:18px; }}
    .feature h3 {{ margin:0 0 8px; font-size:17px; }}
    .feature p {{ margin:0; color:var(--muted); line-height:1.6; font-size:14px; }}
    .steps {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; counter-reset:step; }}
    .step {{ position:relative; background:#07111f; border:1px solid var(--line); border-radius:18px; padding:44px 16px 16px; min-height:150px; }}
    .step:before {{ counter-increment:step; content:counter(step); position:absolute; top:14px; left:16px; width:24px; height:24px; border-radius:999px; background:#1d4ed8; display:grid; place-items:center; font-weight:900; }}
    .step b {{ display:block; margin-bottom:8px; }}
    .step span {{ color:var(--muted); line-height:1.55; font-size:14px; }}
    .positioning {{ font-size:24px; line-height:1.55; color:#e0f2fe; border-left:4px solid var(--blue); padding-left:18px; }}
    .note {{ color:var(--muted); font-size:13px; margin-top:14px; }}
    @media(max-width:900px) {{ .hero{{grid-template-columns:1fr}} h1{{font-size:44px}} .feature-grid,.steps{{grid-template-columns:1fr}} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="nav"><div class="brand"><div class="logo"></div>Bitmap Agent Root Portal</div><div>Memory + Proofs + AI Roles + Skills</div></div>

    <div class="hero">
      <div>
        <div class="eyebrow">Bitcoin-native agent root</div>
        <h1>Turn your Bitmap into an AI Agent Root</h1>
        <p class="subtitle">Root on Bitcoin / Bitmap, Remember with AI</p>
        <p class="body">Bitmap does not need to store every file or every AI thought. It can become the trusted coordinate for a verifiable set of files, signatures, manifests, roles, skills, and privacy-aware agent policies.</p>
        <div class="cta-row">
          <a class="btn primary" href="{_esc(demo_portal_path)}">Open demo portal</a>
          <a class="btn secondary" href="#how">See how it works</a>
        </div>
      </div>
      <div class="demo-card">
        <div class="eyebrow">Live local demo</div>
        <h2>Patoshi Agent Root Portal</h2>
        <div class="metric-grid">
          <div class="metric"><span>Indexed files</span><b>{_esc(demo_files_count)} files</b></div>
          <div class="metric"><span>Portal type</span><b>Human + AI</b></div>
          <div class="metric"><span>Agent</span><b>{_esc(agent_name)}</b></div>
          <div class="metric"><span>Agent root</span><b>{_esc(demo_agent_root_type)}</b></div>
          <div class="metric"><span>Skill pack</span><b>{_esc(demo_skills_count)} skills</b></div>
          <div class="metric"><span>Policy</span><b>Privacy-aware</b></div>
        </div>
        <div class="metric"><span>Manifest Hash</span><div class="hash">{_esc(demo_manifest_hash)}</div></div>
        <div class="metric" style="margin-top:12px"><span>Merkle Root</span><div class="hash">{_esc(demo_merkle_root)}</div></div>
      </div>
    </div>

    <section>
      <h2>What it is</h2>
      <div class="positioning">A Bitmap Agent Root turns a Bitmap coordinate into a trusted homepage for files, versions, signatures, anchors, AI roles, reusable skills, and privacy-aware trust policies.</div>
      <p class="note">It is not a storage layer. It is a proof, index, and AI-operable trust-root layer.</p>
    </section>

    <section>
      <h2>Core capabilities</h2>
      <p class="note">Earlier framing: Turn your Bitmap into a Memory Portal. Delivery framing: Turn your Bitmap into an AI Agent Root.</p>
      <div class="feature-grid">
        <div class="feature"><h3>Human-readable portal</h3><p>A beautiful page for people to understand what this Bitmap memory root represents.</p></div>
        <div class="feature"><h3>Agent-readable root</h3><p>A structured JSON layer that future agents can read to identify trusted files, roles, skills, versions, roots, permissions, and the AI-readable manifest.</p></div>
        <div class="feature"><h3>Tamper verification</h3><p>Recompute hashes and Merkle roots to detect changed, missing, or unexpected files.</p></div>
        <div class="feature"><h3>Reusable skill pack</h3><p>Bind a coordinate to durable capabilities like memory curation, archive verification, investment review, and legacy storytelling.</p></div>
        <div class="feature"><h3>Privacy-aware trust policy</h3><p>Publish summaries, hashes, and proofs while keeping sensitive source files private or encrypted.</p></div>
        <div class="feature"><h3>Family Trust Root</h3><p>Package the same primitive for family offices, creators, investors, and long-term AI memory.</p></div>
      </div>
    </section>

    <section id="how">
      <h2>How it works</h2>
      <div class="steps">
        <div class="step"><b>Choose files</b><span>Select a local archive, research folder, family file set, or AI memory package.</span></div>
        <div class="step"><b>Generate manifest</b><span>Calculate SHA256 for every file and combine them into one Merkle root.</span></div>
        <div class="step"><b>Attach identity</b><span>Record Bitmap coordinate, trusted signer, signature, planned anchors, agent roles, and skill summaries.</span></div>
        <div class="step"><b>Verify later</b><span>Run the verifier to prove whether the folder and AI-operable memory root still match the original manifest.</span></div>
      </div>
    </section>
  </div>
</body>
</html>
"""
