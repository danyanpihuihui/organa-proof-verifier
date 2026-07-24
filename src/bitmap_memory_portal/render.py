from __future__ import annotations

import html
import json
from typing import Dict


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _short(value: str, n: int = 18) -> str:
    value = str(value or "")
    if len(value) <= n * 2 + 3:
        return value
    return value[:n] + "..." + value[-n:]


def render_portal_html(manifest: Dict, proof: Dict) -> str:
    files = manifest.get("files") or []
    file_cards = "".join(
        f"""
        <div class="file-row">
          <div><b>{_esc(f.get('path'))}</b><span>{_esc(f.get('mime_type'))} · {_esc(f.get('size_bytes'))} bytes</span></div>
          <code>{_esc(_short(f.get('sha256'), 16))}</code>
        </div>
        """
        for f in files[:200]
    )
    manifest_json = json.dumps(manifest, ensure_ascii=False, indent=2)
    proof_json = json.dumps(proof, ensure_ascii=False, indent=2)
    signer_cards = "".join(f"<div class='file-row'><div><b>{_esc(s)}</b><span>trusted signer</span></div></div>" for s in (manifest.get("trusted_signers") or []))
    signature_cards = "".join(
        f"<div class='file-row'><div><b>{_esc(sig.get('signer'))}</b><span>{_esc(sig.get('method'))}</span></div><code>{_esc(_short(sig.get('signature'), 18))}</code></div>"
        for sig in (manifest.get("signatures") or [])
    )
    anchor_cards = "".join(
        f"<div class='file-row'><div><b>{_esc(a.get('type'))}</b><span>{_esc(a.get('status'))}</span></div><code>{_esc(_short(a.get('value'), 18))}</code></div>"
        for a in (manifest.get("anchors") or [])
    )
    claim = manifest.get("claim") or {}
    save_point = manifest.get("save_point") or {}
    task_bounty = manifest.get("task_bounty") or {}
    reward_terms = manifest.get("reward_terms") or {}
    handoff_log = manifest.get("handoff_log") or {}
    bounty_verification = manifest.get("bounty_verification") or {}
    bitmap_os = manifest.get("bitmap_os") or {}
    worker = manifest.get("worker") or {}
    public_manifest = manifest.get("public_manifest") or {}
    hash_proof = manifest.get("hash_proof") or {}
    disclosure_policy = manifest.get("disclosure_policy") or {}
    verifier_room = manifest.get("verifier_room") or {}
    reveal_grant = manifest.get("reveal_grant") or {}
    evidence_bundle = manifest.get("evidence_bundle") or {}
    redaction_report = manifest.get("redaction_report") or {}
    active_reveal_grant = manifest.get("active_reveal_grant") or {}
    verifier_result = manifest.get("verifier_result") or {}
    active_grant_section = ""
    if active_reveal_grant:
        active_grant_section = f"""
    <section>
      <h2>Active Grant</h2>
      <p class="desc">This simulated grant shows how a named verifier can receive scoped L3 access to redacted evidence and issue a limited verification result.</p>
      <div class="grid">
        <div class="card"><div class="label">Grant Status</div><div class="value">{_esc(active_reveal_grant.get('grant_status'))}</div></div>
        <div class="card"><div class="label">Verifier</div><div class="value">{_esc((active_reveal_grant.get('recipient') or {}).get('verifier_id'))}</div></div>
        <div class="card"><div class="label">Result</div><div class="value">{_esc(verifier_result.get('result_status'))}</div></div>
        <div class="card"><div class="label">Expires</div><div class="value">{_esc(active_reveal_grant.get('expires_at_utc'))}</div></div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Active Grant</div><div class="value"><a href="active_reveal_grant.json">active_reveal_grant.json</a></div></div>
        <div class="card"><div class="label">Verifier Result</div><div class="value"><a href="verifier_result.json">verifier_result.json</a></div></div>
        <div class="card"><div class="label">Audit Trail</div><div class="value"><a href="active_verifier_audit_log.jsonl">active_verifier_audit_log.jsonl</a></div></div>
        <div class="card"><div class="label">Grant Hash</div><div class="value">{_esc(_short(verifier_result.get('grant_hash'), 10))}</div></div>
      </div>
      <div class="label">Cannot Verify</div>
      <div class="hash">{_esc(', '.join(verifier_result.get('cannot_verify') or []))}</div>
    </section>
        """
    verifier_room_section = ""
    if verifier_room:
        verifier_room_section = f"""
    <section>
      <h2>Verifier Room</h2>
      <p class="desc">L3 selective reveal lets a named verifier inspect a redacted evidence bundle without exposing raw skills, credentials, private memory, or candidate pools.</p>
      <div class="grid">
        <div class="card"><div class="label">Disclosure</div><div class="value">{_esc(verifier_room.get('disclosure_level'))}</div></div>
        <div class="card"><div class="label">Room Status</div><div class="value">{_esc(verifier_room.get('room_status'))}</div></div>
        <div class="card"><div class="label">Grant Status</div><div class="value">{_esc(reveal_grant.get('grant_status'))}</div></div>
        <div class="card"><div class="label">Redaction</div><div class="value">{_esc(redaction_report.get('redaction_status'))}</div></div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Room</div><div class="value"><a href="verifier_room.json">verifier_room.json</a></div></div>
        <div class="card"><div class="label">Grant</div><div class="value"><a href="reveal_grant.json">reveal_grant.json</a></div></div>
        <div class="card"><div class="label">Evidence</div><div class="value"><a href="evidence_bundle.json">evidence_bundle.json</a></div></div>
        <div class="card"><div class="label">Audit</div><div class="value"><a href="verifier_audit_log.jsonl">verifier_audit_log.jsonl</a></div></div>
      </div>
      <div class="label">Source Private Payload Hash</div>
      <div class="hash">{_esc(evidence_bundle.get('source_private_payload_hash'))}</div>
      <div class="label" style="margin-top:16px">Redacted Fields</div>
      <div class="hash">{_esc(', '.join(evidence_bundle.get('redacted_fields') or []))}</div>
      <p class="desc"><a href="redaction_report.json">redaction_report.json</a></p>
    </section>
        """
    bitmap_os_section = ""
    if bitmap_os:
        levels = disclosure_policy.get("levels") or {}
        level_pills = "".join(f"<span class='pill'>{_esc(level)} · {_esc((data or {}).get('name'))}</span>" for level, data in levels.items())
        bitmap_os_section = f"""
    <section>
      <h2>Bitmap OS v0</h2>
      <p class="desc">Public proof for private work: Bitmap OS publishes coordination, hashes, status, and verification boundaries while keeping execution know-how private.</p>
      <div class="grid">
        <div class="card"><div class="label">Product Thesis</div><div class="value">{_esc(bitmap_os.get('product_thesis'))}</div></div>
        <div class="card"><div class="label">Principle</div><div class="value">{_esc(bitmap_os.get('principle'))}</div></div>
        <div class="card"><div class="label">Private Worker</div><div class="value">{_esc(worker.get('worker_id'))}</div></div>
        <div class="card"><div class="label">Disclosure</div><div class="value">{_esc(worker.get('default_disclosure_level'))}</div></div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Policy</div><div class="value"><a href="disclosure_policy.json">disclosure_policy.json</a></div></div>
        <div class="card"><div class="label">Public Manifest</div><div class="value"><a href="public_manifest.json">public_manifest.json</a></div></div>
        <div class="card"><div class="label">Private Manifest</div><div class="value"><a href="private_manifest.json">private_manifest.json</a></div></div>
        <div class="card"><div class="label">Hash Proof</div><div class="value"><a href="hash_proof.json">hash_proof.json</a></div></div>
      </div>
      <div class="label">Disclosure Levels</div>
      <div>{level_pills}</div>
      <div class="label" style="margin-top:16px">Private Payload Hash</div>
      <div class="hash">{_esc(hash_proof.get('private_payload_hash'))}</div>
      <div class="label" style="margin-top:16px">Public Fields</div>
      <div class="hash">{_esc(', '.join(public_manifest.get('public_fields') or []))}</div>
      <p class="desc"><a href="bitmap_os_thesis.json">bitmap_os_thesis.json</a> · <a href="worker.json">worker.json</a> · <a href="workflow.json">workflow.json</a> · <a href="task_inbox.json">task_inbox.json</a> · <a href="run_log.jsonl">run_log.jsonl</a> · <a href="selective_reveal_policy.json">selective_reveal_policy.json</a></p>
    </section>
        """
    bounty_quest_section = ""
    if task_bounty:
        bounty_quest_section = f"""
    <section>
      <h2>Bounty Quest</h2>
      <p class="desc">A game-like bounty layer for urgent important real-world tasks: sponsors can fund, solvers can pick up scoped work, and verifiers approve payout after a new save point is produced.</p>
      <div class="grid">
        <div class="card"><div class="label">Quest Status</div><div class="value">{_esc(task_bounty.get('quest_status'))}</div></div>
        <div class="card"><div class="label">Bounty Verify</div><div class="value">{_esc(bounty_verification.get('overall_status'))}</div></div>
        <div class="card"><div class="label">Reward</div><div class="value">{_esc(reward_terms.get('reward_status'))}</div></div>
        <div class="card"><div class="label">Phase</div><div class="value">{_esc(handoff_log.get('current_phase'))}</div></div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Bounty</div><div class="value"><a href="task_bounty.json">task_bounty.json</a></div></div>
        <div class="card"><div class="label">Reward Terms</div><div class="value"><a href="reward_terms.json">reward_terms.json</a></div></div>
        <div class="card"><div class="label">Handoff Log</div><div class="value"><a href="handoff_log.json">handoff_log.json</a></div></div>
        <div class="card"><div class="label">Verification</div><div class="value"><a href="bounty_verification.json">bounty_verification.json</a></div></div>
      </div>
      <div class="label">Quest Rule</div>
      <div class="hash">{_esc(task_bounty.get('quest_rule'))}</div>
    </section>
        """
    anchor_request = manifest.get("anchor_request") or {}
    verify_report = manifest.get("verify_report") or {}
    save_point_section = ""
    if save_point:
        save_point_section = f"""
    <section>
      <h2>Real-world Save Point</h2>
      <p class="desc">This is a milestone checkpoint for a real-world task: files stay in ordinary storage, while the Bitmap coordinate carries the canonical proof root and recovery path.</p>
      <div class="grid">
        <div class="card"><div class="label">Save Point Type</div><div class="value">{_esc(save_point.get('save_point_type'))}</div></div>
        <div class="card"><div class="label">Canonical Status</div><div class="value">{_esc(save_point.get('canonical_status'))}</div></div>
        <div class="card"><div class="label">Timestamp</div><div class="value">{_esc(save_point.get('timestamp_status'))}</div></div>
        <div class="card"><div class="label">Verify</div><div class="value">{_esc(verify_report.get('overall_status'))}</div></div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Save Point</div><div class="value"><a href="save_point.json">save_point.json</a></div></div>
        <div class="card"><div class="label">Anchor Request</div><div class="value"><a href="anchor_request.json">anchor_request.json</a></div></div>
        <div class="card"><div class="label">Verify Report</div><div class="value"><a href="verify_report.json">verify_report.json</a></div></div>
        <div class="card"><div class="label">Policy</div><div class="value">{_esc(save_point.get('checkpoint_policy'))}</div></div>
      </div>
      <div class="label">Storage Boundary</div>
      <div class="hash">{_esc(save_point.get('storage_boundary'))}</div>
      <div class="label" style="margin-top:16px">Hash to Anchor</div>
      <div class="hash">{_esc(anchor_request.get('hash_to_anchor'))}</div>
    </section>
        """
    task_root = manifest.get("task_root") or {}
    priority_sources = manifest.get("priority_sources") or {}
    digging_policy = manifest.get("digging_policy") or {}
    priority_cards = "".join(
        f"<div class='file-row'><div><b>{_esc(src.get('path'))}</b><span>{_esc(src.get('deep_dig_priority'))} · {_esc(src.get('trust_basis'))}</span></div><code>{_esc(_short(src.get('sha256'), 16))}</code></div>"
        for src in (priority_sources.get("sources") or [])[:8]
    )
    task_root_section = ""
    if task_root:
        task_root_section = f"""
    <section>
      <h2>Bitmap Task Root</h2>
      <p class="desc">This coordinate is a task bootloader for AI agents: load the task root, authenticity label, proof, agent policy, priority sources, and digging rules before answering.</p>
      <div class="grid">
        <div class="card"><div class="label">Root Type</div><div class="value">{_esc(task_root.get('root_type'))}</div></div>
        <div class="card"><div class="label">Coordinate</div><div class="value">{_esc(task_root.get('coordinate'))}</div></div>
        <div class="card"><div class="label">Authenticity</div><div class="value">{_esc(task_root.get('authenticity_status'))}</div></div>
        <div class="card"><div class="label">Priority Sources</div><div class="value">{_esc(task_root.get('priority_sources_count'))}</div></div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Task Root</div><div class="value"><a href="task_root.json">task_root.json</a></div></div>
        <div class="card"><div class="label">Priority Sources</div><div class="value"><a href="priority_sources.json">priority_sources.json</a></div></div>
        <div class="card"><div class="label">Digging Policy</div><div class="value"><a href="digging_policy.json">digging_policy.json</a></div></div>
        <div class="card"><div class="label">Primary Task</div><div class="value">{_esc((task_root.get('task_identity') or {}).get('primary_task'))}</div></div>
      </div>
      <div class="label">Clone Boundary</div>
      <div class="hash">{_esc((task_root.get('clone_boundary') or {}).get('copying_rule'))}</div>
      <div class="label" style="margin-top:16px">High-priority sources</div>
      {priority_cards or '<div class="label">No priority sources recorded yet.</div>'}
      <div class="label" style="margin-top:16px">Digging rule</div>
      <div class="hash">{_esc('; '.join((digging_policy.get('agent_rules') or [])[:3]))}</div>
    </section>
        """
    authenticity = manifest.get("authenticity") or {}
    authenticity_layers = authenticity.get("evidence_layers") or []
    authenticity_cards = "".join(
        f"<div class='file-row'><div><b>{_esc(layer.get('layer'))}</b><span>{_esc(layer.get('status'))}</span></div><code>{_esc(_short(layer.get('evidence'), 24))}</code></div>"
        for layer in authenticity_layers
    )
    authenticity_section = ""
    if authenticity:
        authenticity_section = f"""
    <section>
      <h2>Authenticity Label</h2>
      <p class="desc">This label summarizes what makes this public data set authentic, and what is still not proven.</p>
      <div class="grid">
        <div class="card"><div class="label">Coordinate</div><div class="value">{_esc(authenticity.get('coordinate'))}</div></div>
        <div class="card"><div class="label">Overall Status</div><div class="value">{_esc(authenticity.get('authenticity_status'))}</div></div>
        <div class="card"><div class="label">Data Scope</div><div class="value">{_esc(authenticity.get('data_scope'))}</div></div>
        <div class="card"><div class="label">Label File</div><div class="value"><a href="authenticity.json">authenticity.json</a></div></div>
      </div>
      {authenticity_cards}
    </section>
        """
    claim_section = ""
    if claim:
        claim_section = f"""
    <section>
      <h2>Signed Wallet Claim</h2>
      <p class="desc">This claim records the wallet attestation for the Bitmap Memory Portal. Signature verification status is reported separately from the presence of a signature.</p>
      <div class="grid">
        <div class="card"><div class="label">Claim Status</div><div class="value">{_esc(claim.get('claim_status'))}</div></div>
        <div class="card"><div class="label">Steward</div><div class="value">{_esc(claim.get('steward'))}</div></div>
        <div class="card"><div class="label">Signature Method</div><div class="value">{_esc(claim.get('signature_method'))}</div></div>
        <div class="card"><div class="label">Local Verification</div><div class="value">{_esc(claim.get('signature_verification'))}</div></div>
      </div>
      <div class="label">Signing Address</div>
      <div class="hash">{_esc(claim.get('signing_address'))}</div>
      <div class="label" style="margin-top:14px">Signature</div>
      <div class="hash">{_esc(_short(claim.get('signature'), 42))}</div>
      <p class="desc"><a href="claim_7187.json">Open claim_7187.json</a></p>
    </section>
        """
    citations = manifest.get("citations") or {}
    citation_items = citations.get("citations") or []
    citation_cards = "".join(
        f"<div class='file-row'><div><b>{_esc(item.get('target_bitmap'))}</b><span>{_esc(item.get('relation'))} · {_esc(item.get('weight'))} · {_esc(item.get('verification_status'))}</span><span>{_esc(item.get('note'))}</span></div><code>{_esc(_short(item.get('evidence'), 18))}</code></div>"
        for item in citation_items
    )
    citations_section = ""
    if citations:
        citations_section = f"""
    <section>
      <h2>Bitmap Citation Graph</h2>
      <p class="desc">This section records Bitmap-to-Bitmap references. A Bitmap cited by other Bitmaps can accumulate structural confirmation, similar to a trust graph.</p>
      <div class="grid">
        <div class="card"><div class="label">Source Bitmap</div><div class="value">{_esc(citations.get('source_bitmap'))}</div></div>
        <div class="card"><div class="label">Citations</div><div class="value">{_esc(len(citation_items))}</div></div>
        <div class="card"><div class="label">Schema</div><div class="value">{_esc(citations.get('schema_version'))}</div></div>
        <div class="card"><div class="label">Graph File</div><div class="value"><a href="citations.json">citations.json</a></div></div>
      </div>
      {citation_cards or '<div class="label">No Bitmap citations recorded yet.</div>'}
    </section>
        """
    agent_root = manifest.get("agent_root") or {}
    skill_cards = "".join(
        f"<div class='file-row'><div><b>{_esc(skill.get('title') or skill.get('id'))}</b><span>{_esc(skill.get('id'))} · {_esc(skill.get('visibility'))}</span><span>{_esc(skill.get('description'))}</span></div></div>"
        for skill in (agent_root.get("skills") or [])
    )
    role_pills = "".join(f"<span class='pill'>{_esc(role)}</span>" for role in (agent_root.get("roles") or []))
    agent_section = ""
    if agent_root:
        agent_section = f"""
    <section>
      <h2>AI Agent Root</h2>
      <p class="desc">This Bitmap coordinate is also an AI-operable root: future agents should load the agent policy, skills, and trust rules before interpreting the archive.</p>
      <div class="grid">
        <div class="card"><div class="label">Agent Name</div><div class="value">{_esc(agent_root.get('agent_name'))}</div></div>
        <div class="card"><div class="label">Agent Root Type</div><div class="value">{_esc(agent_root.get('agent_root_type'))}</div></div>
        <div class="card"><div class="label">Roles</div><div class="value">{_esc(len(agent_root.get('roles') or []))}</div></div>
        <div class="card"><div class="label">Skills</div><div class="value">{_esc(len(agent_root.get('skills') or []))}</div></div>
      </div>
      <div class="label">Purpose</div>
      <p class="desc">{_esc(agent_root.get('purpose'))}</p>
      <div class="label">Roles</div>
      <div>{role_pills}</div>
      <div class="label" style="margin-top:16px">Skills</div>
      {skill_cards or '<div class="label">No agent skills recorded yet.</div>'}
      <div class="label" style="margin-top:16px">Public Portal Rule</div>
      <div class="hash">{_esc((agent_root.get('trust_policy') or {}).get('public_portal_rule'))}</div>
    </section>
        """
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_esc(manifest.get('title'))}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#050816; --panel:#0f172a; --panel2:#111827; --line:#253047; --text:#e5e7eb; --muted:#94a3b8; --blue:#60a5fa; --green:#22c55e; --amber:#f59e0b; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:radial-gradient(circle at top left,#172554 0,#050816 38%,#020617 100%); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif; }}
    .wrap {{ max-width:1180px; margin:0 auto; padding:36px 20px 60px; }}
    .hero {{ border:1px solid rgba(96,165,250,.28); background:linear-gradient(135deg,rgba(15,23,42,.94),rgba(17,24,39,.88)); border-radius:28px; padding:34px; box-shadow:0 24px 80px rgba(0,0,0,.35); }}
    .eyebrow {{ color:var(--blue); font-weight:800; letter-spacing:.08em; text-transform:uppercase; font-size:12px; }}
    h1 {{ margin:12px 0 10px; font-size:42px; line-height:1.08; }}
    .tagline {{ color:#bfdbfe; font-size:19px; margin:0 0 18px; }}
    .desc {{ color:var(--muted); max-width:780px; line-height:1.7; }}
    .grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:22px 0; }}
    .card {{ background:rgba(15,23,42,.82); border:1px solid var(--line); border-radius:18px; padding:16px; }}
    .label {{ color:var(--muted); font-size:12px; margin-bottom:8px; }}
    .value {{ font-size:20px; font-weight:800; word-break:break-all; }}
    section {{ margin-top:22px; padding:22px; border:1px solid var(--line); border-radius:22px; background:rgba(15,23,42,.78); }}
    h2 {{ margin:0 0 14px; font-size:22px; }}
    .hash {{ color:#bbf7d0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; word-break:break-all; background:#07111f; border:1px solid #164e32; border-radius:12px; padding:12px; }}
    .file-row {{ display:flex; align-items:center; justify-content:space-between; gap:16px; padding:12px 0; border-bottom:1px solid rgba(148,163,184,.16); }}
    .file-row span {{ display:block; color:var(--muted); font-size:12px; margin-top:4px; }}
    code, pre {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
    .file-row code {{ color:#93c5fd; font-size:12px; }}
    details {{ margin-top:12px; }}
    summary {{ cursor:pointer; color:#fbbf24; font-weight:700; }}
    pre {{ white-space:pre-wrap; overflow:auto; max-height:460px; background:#020617; border:1px solid #1e293b; border-radius:16px; padding:16px; color:#d1d5db; font-size:12px; }}
    .pill {{ display:inline-flex; padding:7px 10px; border-radius:999px; background:rgba(34,197,94,.13); color:#86efac; border:1px solid rgba(34,197,94,.32); font-weight:700; font-size:12px; margin-right:8px; }}
    @media(max-width:860px) {{ .grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} h1{{font-size:32px}} .file-row{{align-items:flex-start; flex-direction:column}} }}
  </style>
</head>
<body>
  <main class="wrap">
    <div class="hero">
      <div class="eyebrow">Bitmap Memory Portal</div>
      <h1>{_esc(manifest.get('title'))}</h1>
      <p class="tagline">Root on Bitcoin / Bitmap, Remember with AI</p>
      <p class="desc">{_esc(manifest.get('description'))}</p>
      <span class="pill">Human-readable portal</span><span class="pill">AI-readable Manifest</span><span class="pill">Verifiable file root</span>
    </div>

    <div class="grid">
      <div class="card"><div class="label">Bitmap Coordinate</div><div class="value">{_esc(manifest.get('bitmap'))}</div></div>
      <div class="card"><div class="label">Version</div><div class="value">{_esc(manifest.get('version'))}</div></div>
      <div class="card"><div class="label">Files</div><div class="value">{_esc(manifest.get('files_count'))}</div></div>
      <div class="card"><div class="label">Total Size</div><div class="value">{_esc(manifest.get('total_size_bytes'))} bytes</div></div>
    </div>

    <section>
      <h2>Trust Root</h2>
      <div class="label">Manifest Hash</div>
      <div class="hash">{_esc(manifest.get('manifest_hash'))}</div>
      <div class="label" style="margin-top:14px">Merkle Root</div>
      <div class="hash">{_esc(manifest.get('merkle_root'))}</div>
    </section>

    {save_point_section}

    {bitmap_os_section}

    {verifier_room_section}

    {active_grant_section}

    {bounty_quest_section}

    {task_root_section}

    {authenticity_section}

    <section>
      <h2>Ask AI about this Bitmap</h2>
      <p class="desc">Use this portal as a context package for an AI assistant. The assistant should read the prompt and proof files before answering, then separate sourced facts from thesis and missing evidence.</p>
      <div class="grid">
        <div class="card"><div class="label">Prompt</div><div class="value"><a href="ask_ai_prompt.md">ask_ai_prompt.md</a></div></div>
        <div class="card"><div class="label">Manifest</div><div class="value"><a href="manifest.json">manifest.json</a></div></div>
        <div class="card"><div class="label">Proof</div><div class="value"><a href="proof.json">proof.json</a></div></div>
        <div class="card"><div class="label">Agent</div><div class="value"><a href="agent.json">agent.json</a></div></div>
      </div>
      <div class="label">AI discipline</div>
      <div class="hash">Do not claim verified chain ownership. Do not claim verified Bitcoin block attributes. Answer using Source-backed facts, Working thesis, Unverified assumptions, and evidence needed.</div>
    </section>

    {claim_section}

    {citations_section}

    {agent_section}

    <section>
      <h2>Signers & Anchors</h2>
      <div class="label">Trusted Signers</div>
      {signer_cards or '<div class="label">No trusted signer recorded yet.</div>'}
      <div class="label" style="margin-top:16px">Signatures</div>
      {signature_cards or '<div class="label">No signature recorded yet.</div>'}
      <div class="label" style="margin-top:16px">Anchors</div>
      {anchor_cards or '<div class="label">No chain/timestamp anchor recorded yet.</div>'}
    </section>

    <section>
      <h2>Files in this Memory Root</h2>
      {file_cards or '<div class="label">No files indexed.</div>'}
    </section>

    <section>
      <h2>AI-readable Manifest</h2>
      <p class="desc">AI agents should read this JSON to identify the trusted source set, verify file hashes, and understand the current version root.</p>
      <details open><summary>manifest.json</summary><pre>{_esc(manifest_json)}</pre></details>
      <details><summary>proof.json</summary><pre>{_esc(proof_json)}</pre></details>
    </section>
  </main>
</body>
</html>
"""


def render_ask_ai_prompt(manifest: Dict, proof: Dict) -> str:
    agent_root = manifest.get("agent_root") or {}
    files = manifest.get("files") or []
    file_list = "\n".join(f"- `{f.get('path')}` ({f.get('mime_type')}, sha256:{f.get('sha256')})" for f in files)
    roles = ", ".join(agent_root.get("roles") or []) or "not specified"
    return f"""# Ask AI About {manifest.get('bitmap')}

Use this prompt when asking an AI assistant to interpret this Bitmap Memory Portal.

## Required context files

Load these files before answering:

1. `manifest.json`
2. `proof.json`
3. `agent.json`
4. The source files listed in `manifest.json`, if available and authorized.

## Trust root

- Bitmap: `{manifest.get('bitmap')}`
- Title: `{manifest.get('title')}`
- Version: `{manifest.get('version')}`
- Manifest hash: `{manifest.get('manifest_hash')}`
- Merkle root: `{manifest.get('merkle_root')}`
- Proof status: `{proof.get('status')}`
- Agent name: `{agent_root.get('agent_name', '-')}`
- Agent roles: `{roles}`

## Source files

{file_list or '- No source files recorded.'}

## Instructions for the AI assistant

1. Treat the Bitmap coordinate as the stable trust root, not as the full storage layer.
2. Verify or at least cite `manifest.json` and `proof.json` before making claims about the archive.
3. Distinguish source-backed facts from speculative thesis.
4. Preserve privacy boundaries. Do not infer private wallet balances, trades, or identities beyond the sources.
5. When discussing human memories, use careful language and do not turn gratitude into marketing copy.

## Good first questions

- What does this Bitmap represent?
- Which sources are included in this memory root?
- What is the Bitcoin / Bitmap / AI trust-root thesis here?
- What would need to be signed or anchored before this becomes stronger evidence?
"""
