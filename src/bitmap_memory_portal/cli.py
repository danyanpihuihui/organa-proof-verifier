from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from .active_grant import build_active_grant_bundle
from .bitmap_os import build_bitmap_os_bundle
from .bounty_quest import build_bounty_quest_bundle
from .core import build_agent_root, build_ask_context_pack, build_manifest, build_proof, verify_manifest
from .authenticity import build_authenticity_label
from .claims import verify_claim_signature
from .cell_resolution import build_cell_resolution_package, verify_cell_resolution_package
from .render import render_ask_ai_prompt, render_portal_html
from .graph import build_citation_graph
from .graph_render import render_graph_html
from .graphify_adapter import build_graphify_checkpoint
from .landing import render_landing_html
from .publish import publish_static_site
from .save_point import build_save_point_bundle
from .selective_reveal import build_selective_reveal_bundle
from .task_root import build_task_root_bundle


def _write_bitmap_os_files(out: Path, bitmap_os_bundle: dict) -> None:
    (out / "bitmap_os_thesis.json").write_text(json.dumps(bitmap_os_bundle["bitmap_os"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "worker.json").write_text(json.dumps(bitmap_os_bundle["worker"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "workflow.json").write_text(json.dumps(bitmap_os_bundle["workflow"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "task_inbox.json").write_text(json.dumps(bitmap_os_bundle["task_inbox"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "disclosure_policy.json").write_text(json.dumps(bitmap_os_bundle["disclosure_policy"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "public_manifest.json").write_text(json.dumps(bitmap_os_bundle["public_manifest"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "private_manifest.json").write_text(json.dumps(bitmap_os_bundle["private_manifest"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "hash_proof.json").write_text(json.dumps(bitmap_os_bundle["hash_proof"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "selective_reveal_policy.json").write_text(json.dumps(bitmap_os_bundle["selective_reveal_policy"], ensure_ascii=False, indent=2), encoding="utf-8")
    run_log = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in bitmap_os_bundle["run_log"])
    (out / "run_log.jsonl").write_text(run_log, encoding="utf-8")


def _write_selective_reveal_files(out: Path, selective_reveal_bundle: dict) -> None:
    (out / "verifier_room.json").write_text(json.dumps(selective_reveal_bundle["verifier_room"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "reveal_grant.json").write_text(json.dumps(selective_reveal_bundle["reveal_grant"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "evidence_bundle.json").write_text(json.dumps(selective_reveal_bundle["evidence_bundle"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "redaction_report.json").write_text(json.dumps(selective_reveal_bundle["redaction_report"], ensure_ascii=False, indent=2), encoding="utf-8")
    audit_log = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in selective_reveal_bundle["verifier_audit_log"])
    (out / "verifier_audit_log.jsonl").write_text(audit_log, encoding="utf-8")


def _write_active_grant_files(out: Path, active_grant_bundle: dict) -> None:
    (out / "active_reveal_grant.json").write_text(json.dumps(active_grant_bundle["active_reveal_grant"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "verifier_result.json").write_text(json.dumps(active_grant_bundle["verifier_result"], ensure_ascii=False, indent=2), encoding="utf-8")
    audit_log = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in active_grant_bundle["active_verifier_audit_log"])
    (out / "active_verifier_audit_log.jsonl").write_text(audit_log, encoding="utf-8")


def _agent_skills_from_args(args: argparse.Namespace):
    return [
        {"id": skill_id, "title": title, "description": description}
        for skill_id, title, description in (args.agent_skill or [])
    ]


def _build_agent_root_from_args(args: argparse.Namespace):
    agent_skills = _agent_skills_from_args(args)
    return build_agent_root(
        bitmap=args.bitmap,
        title=args.title,
        version=args.version,
        agent_name=args.agent_name,
        purpose=args.agent_purpose,
        roles=args.agent_role,
        skills=agent_skills or None,
    )


def _claim_from_args(args: argparse.Namespace):
    claim_path = getattr(args, "claim", None)
    if not claim_path:
        return None
    claim = json.loads(Path(claim_path).expanduser().resolve().read_text(encoding="utf-8"))
    return verify_claim_signature(claim)


def _citations_from_args(args: argparse.Namespace):
    citations_path = getattr(args, "citations", None)
    if not citations_path:
        return None
    return json.loads(Path(citations_path).expanduser().resolve().read_text(encoding="utf-8"))


def generate(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    agent_root = _build_agent_root_from_args(args)
    claim = _claim_from_args(args)
    citations = _citations_from_args(args)

    manifest = build_manifest(
        source_dir=source,
        bitmap=args.bitmap,
        title=args.title,
        version=args.version,
        previous_manifest_hash=args.previous_manifest_hash,
        description=args.description or "",
        signers=args.signer or [],
        signatures=[{"signer": s, "signature": sig, "method": "manual"} for s, sig in (args.signature or [])],
        anchors=[{"type": t, "status": status, "value": value} for t, status, value in (args.anchor or [])],
        agent_root=agent_root,
        claim=claim,
        citations=citations,
    )
    authenticity = build_authenticity_label(manifest)
    manifest["authenticity"] = authenticity
    task_bundle = build_task_root_bundle(manifest, authenticity)
    manifest.update(task_bundle)
    save_point_bundle = build_save_point_bundle(manifest)
    manifest.update(save_point_bundle)
    bounty_quest_bundle = build_bounty_quest_bundle(manifest)
    manifest.update(bounty_quest_bundle)
    bitmap_os_bundle = build_bitmap_os_bundle(manifest)
    manifest.update(bitmap_os_bundle)
    selective_reveal_bundle = build_selective_reveal_bundle(manifest)
    manifest.update(selective_reveal_bundle)
    active_grant_bundle = build_active_grant_bundle(manifest)
    manifest.update(active_grant_bundle)
    manifest["manifest_hash"] = manifest["manifest_hash"]
    proof = build_proof(manifest)
    html = render_portal_html(manifest, proof)
    ask_ai_prompt = render_ask_ai_prompt(manifest, proof)

    manifest_path = out / "manifest.json"
    proof_path = out / "proof.json"
    agent_path = out / "agent.json"
    ask_ai_path = out / "ask_ai_prompt.md"
    html_path = out / "portal.html"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    proof_path.write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8")
    agent_path.write_text(json.dumps(agent_root, ensure_ascii=False, indent=2), encoding="utf-8")
    ask_ai_path.write_text(ask_ai_prompt, encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")
    if claim:
        (out / "claim_7187.json").write_text(json.dumps(claim, ensure_ascii=False, indent=2), encoding="utf-8")
    if citations:
        (out / "citations.json").write_text(json.dumps(citations, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "authenticity.json").write_text(json.dumps(authenticity, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "task_root.json").write_text(json.dumps(task_bundle["task_root"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "priority_sources.json").write_text(json.dumps(task_bundle["priority_sources"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "digging_policy.json").write_text(json.dumps(task_bundle["digging_policy"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "save_point.json").write_text(json.dumps(save_point_bundle["save_point"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "anchor_request.json").write_text(json.dumps(save_point_bundle["anchor_request"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "verify_report.json").write_text(json.dumps(save_point_bundle["verify_report"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "task_bounty.json").write_text(json.dumps(bounty_quest_bundle["task_bounty"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "reward_terms.json").write_text(json.dumps(bounty_quest_bundle["reward_terms"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "handoff_log.json").write_text(json.dumps(bounty_quest_bundle["handoff_log"], ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "bounty_verification.json").write_text(json.dumps(bounty_quest_bundle["bounty_verification"], ensure_ascii=False, indent=2), encoding="utf-8")
    _write_bitmap_os_files(out, bitmap_os_bundle)
    _write_selective_reveal_files(out, selective_reveal_bundle)
    _write_active_grant_files(out, active_grant_bundle)

    print(json.dumps({
        "manifest_path": str(manifest_path),
        "proof_path": str(proof_path),
        "agent_path": str(agent_path),
        "ask_ai_prompt_path": str(ask_ai_path),
        "portal_html_path": str(html_path),
        "manifest_hash": manifest["manifest_hash"],
        "merkle_root": manifest["merkle_root"],
        "files_count": manifest["files_count"],
    }, ensure_ascii=False, indent=2))
    return 0


def _write_zip_from_dir(source_dir: Path, zip_path: Path) -> None:
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for path in sorted(Path(source_dir).rglob("*")):
            if path.is_file():
                z.write(path, path.relative_to(source_dir).as_posix())


def build_package(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    if out.exists() and args.clean:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    demo_dir = out / "demo"
    landing_dir = out / "landing"
    public_dir = out / "public"
    demo_dir.mkdir(parents=True, exist_ok=True)
    landing_dir.mkdir(parents=True, exist_ok=True)

    agent_root = _build_agent_root_from_args(args)
    claim = _claim_from_args(args)
    citations = _citations_from_args(args)
    manifest = build_manifest(
        source_dir=source,
        bitmap=args.bitmap,
        title=args.title,
        version=args.version,
        previous_manifest_hash=args.previous_manifest_hash,
        description=args.description or "",
        signers=args.signer or [],
        signatures=[{"signer": s, "signature": sig, "method": "manual"} for s, sig in (args.signature or [])],
        anchors=[{"type": t, "status": status, "value": value} for t, status, value in (args.anchor or [])],
        agent_root=agent_root,
        claim=claim,
        citations=citations,
    )
    authenticity = build_authenticity_label(manifest)
    manifest["authenticity"] = authenticity
    task_bundle = build_task_root_bundle(manifest, authenticity)
    manifest.update(task_bundle)
    save_point_bundle = build_save_point_bundle(manifest)
    manifest.update(save_point_bundle)
    bounty_quest_bundle = build_bounty_quest_bundle(manifest)
    manifest.update(bounty_quest_bundle)
    bitmap_os_bundle = build_bitmap_os_bundle(manifest)
    manifest.update(bitmap_os_bundle)
    selective_reveal_bundle = build_selective_reveal_bundle(manifest)
    manifest.update(selective_reveal_bundle)
    active_grant_bundle = build_active_grant_bundle(manifest)
    manifest.update(active_grant_bundle)
    manifest["manifest_hash"] = manifest["manifest_hash"]
    proof = build_proof(manifest)
    portal_html = render_portal_html(manifest, proof)
    ask_ai_prompt = render_ask_ai_prompt(manifest, proof)

    (demo_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "proof.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "agent.json").write_text(json.dumps(agent_root, ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "ask_ai_prompt.md").write_text(ask_ai_prompt, encoding="utf-8")
    (demo_dir / "portal.html").write_text(portal_html, encoding="utf-8")
    if claim:
        (demo_dir / "claim_7187.json").write_text(json.dumps(claim, ensure_ascii=False, indent=2), encoding="utf-8")
    if citations:
        (demo_dir / "citations.json").write_text(json.dumps(citations, ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "authenticity.json").write_text(json.dumps(authenticity, ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "task_root.json").write_text(json.dumps(task_bundle["task_root"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "priority_sources.json").write_text(json.dumps(task_bundle["priority_sources"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "digging_policy.json").write_text(json.dumps(task_bundle["digging_policy"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "save_point.json").write_text(json.dumps(save_point_bundle["save_point"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "anchor_request.json").write_text(json.dumps(save_point_bundle["anchor_request"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "verify_report.json").write_text(json.dumps(save_point_bundle["verify_report"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "task_bounty.json").write_text(json.dumps(bounty_quest_bundle["task_bounty"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "reward_terms.json").write_text(json.dumps(bounty_quest_bundle["reward_terms"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "handoff_log.json").write_text(json.dumps(bounty_quest_bundle["handoff_log"], ensure_ascii=False, indent=2), encoding="utf-8")
    (demo_dir / "bounty_verification.json").write_text(json.dumps(bounty_quest_bundle["bounty_verification"], ensure_ascii=False, indent=2), encoding="utf-8")
    _write_bitmap_os_files(demo_dir, bitmap_os_bundle)
    _write_selective_reveal_files(demo_dir, selective_reveal_bundle)
    _write_active_grant_files(demo_dir, active_grant_bundle)

    verify_result = verify_manifest(manifest, source)
    (out / "verify_ok.json").write_text(json.dumps(verify_result, ensure_ascii=False, indent=2), encoding="utf-8")

    landing_html = render_landing_html(
        demo_portal_path="../demo/portal.html",
        demo_manifest_hash=manifest["manifest_hash"],
        demo_merkle_root=manifest["merkle_root"],
        demo_files_count=manifest["files_count"],
        agent_name=agent_root["agent_name"],
        demo_agent_root_type=agent_root["agent_root_type"],
        demo_skills_count=len(agent_root.get("skills") or []),
    )
    landing_path = landing_dir / "landing.html"
    landing_path.write_text(landing_html, encoding="utf-8")

    publish_result = publish_static_site(
        landing_html=landing_path,
        demo_dir=demo_dir,
        out_dir=public_dir,
        project_name=args.project_name,
    )
    zip_path = out / args.zip_name
    _write_zip_from_dir(public_dir, zip_path)

    print(json.dumps({
        "out_dir": str(out),
        "demo_dir": str(demo_dir),
        "landing_html_path": str(landing_path),
        "public_dir": str(public_dir),
        "zip_path": str(zip_path),
        "manifest_hash": manifest["manifest_hash"],
        "merkle_root": manifest["merkle_root"],
        "files_count": manifest["files_count"],
        "agent_name": agent_root["agent_name"],
        "skills_count": len(agent_root.get("skills") or []),
        "verify_ok": verify_result["ok"],
        "publish": publish_result,
    }, ensure_ascii=False, indent=2))
    return 0 if verify_result["ok"] else 2


def verify(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    result = verify_manifest(manifest, source)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 2


def landing(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    html = render_landing_html(
        demo_portal_path=args.demo_portal,
        demo_manifest_hash=args.manifest_hash,
        demo_merkle_root=args.merkle_root,
        demo_files_count=args.files_count,
        agent_name=args.agent_name,
        demo_agent_root_type=args.agent_root_type,
        demo_skills_count=args.skills_count,
    )
    landing_path = out / "landing.html"
    landing_path.write_text(html, encoding="utf-8")
    print(json.dumps({"landing_html_path": str(landing_path)}, ensure_ascii=False, indent=2))
    return 0


def publish(args: argparse.Namespace) -> int:
    result = publish_static_site(
        landing_html=Path(args.landing).expanduser().resolve(),
        demo_dir=Path(args.demo_dir).expanduser().resolve(),
        out_dir=Path(args.out).expanduser().resolve(),
        project_name=args.project_name,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def ask(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve()
    proof_path = Path(args.proof).expanduser().resolve()
    agent_path = Path(args.agent).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    agent = json.loads(agent_path.read_text(encoding="utf-8"))
    pack = build_ask_context_pack(source, manifest, proof, agent, args.question)
    out.write_text(pack["content"], encoding="utf-8")
    print(json.dumps({
        "ask_context_path": str(out),
        "bitmap": manifest.get("bitmap"),
        "question": args.question,
        "included_sources": pack["included_sources"],
    }, ensure_ascii=False, indent=2))
    return 0


def graph(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    citations_files = [Path(p).expanduser().resolve() for p in args.citations]
    data = build_citation_graph(citations_files)
    graph_json_path = out / "graph.json"
    graph_html_path = out / "graph.html"
    graph_json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    graph_html_path.write_text(render_graph_html(data), encoding="utf-8")
    print(json.dumps({
        "graph_json_path": str(graph_json_path),
        "graph_html_path": str(graph_html_path),
        "node_count": data["node_count"],
        "edge_count": data["edge_count"],
    }, ensure_ascii=False, indent=2))
    return 0


def _graphify_executable() -> str:
    configured = os.environ.get("GRAPHIFY_BIN")
    if configured:
        return configured
    discovered = shutil.which("graphify")
    if discovered:
        return discovered
    uv_tool_path = Path.home() / ".local" / "bin" / "graphify"
    if uv_tool_path.exists():
        return str(uv_tool_path)
    raise FileNotFoundError(
        "graphify executable not found; install with `uv tool install graphifyy` "
        "or set GRAPHIFY_BIN"
    )


def _graphify_version(executable: str) -> str:
    result = subprocess.run(
        [executable, "--version"],
        text=True,
        capture_output=True,
        check=True,
    )
    parts = result.stdout.strip().split()
    return parts[-1] if parts else "unknown"


def graphify_checkpoint(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    executable = _graphify_executable()
    command = [
        executable,
        "extract",
        str(source),
        "--out",
        str(out),
        "--code-only",
        "--no-cluster",
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=True)
    graph_path = out / "graphify-out" / "graph.json"
    checkpoint = build_graphify_checkpoint(
        graph_path=graph_path,
        source_path=source,
        graphify_version=_graphify_version(executable),
        command=command,
    )
    checkpoint_path = out / "organa_graph_checkpoint.json"
    checkpoint_path.write_text(
        json.dumps(checkpoint, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps({
        "checkpoint_path": str(checkpoint_path),
        "graph_path": str(graph_path),
        "graph_sha256": checkpoint["graph_sha256"],
        "node_count": checkpoint["node_count"],
        "edge_count": checkpoint["edge_count"],
        "canonical_state_mutation": checkpoint["canonical_state_mutation"],
        "extract_log": completed.stdout.strip().splitlines(),
    }, ensure_ascii=False, indent=2))
    return 0


def _add_agent_root_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", required=True, help="Source folder to index")
    parser.add_argument("--out", required=True, help="Output folder")
    parser.add_argument("--bitmap", required=True, help="Bitmap coordinate, e.g. 981213.bitmap")
    parser.add_argument("--title", required=True, help="Portal title")
    parser.add_argument("--version", required=True, help="Archive version label")
    parser.add_argument("--description", default="", help="Portal description")
    parser.add_argument("--previous-manifest-hash", default=None, help="Previous manifest hash for version chaining")
    parser.add_argument("--signer", action="append", help="Trusted signer address/identifier; repeatable")
    parser.add_argument("--signature", nargs=2, metavar=("SIGNER", "SIGNATURE"), action="append", help="Manual signature pair; repeatable")
    parser.add_argument("--anchor", nargs=3, metavar=("TYPE", "STATUS", "VALUE"), action="append", help="Anchor record, e.g. opentimestamps planned ots://...; repeatable")
    parser.add_argument("--agent-name", default="Bitmap Memory Guardian", help="Agent name for agent.json and AI Agent Root section")
    parser.add_argument("--agent-purpose", default=None, help="Agent purpose statement")
    parser.add_argument("--agent-role", action="append", help="Agent role id; repeatable")
    parser.add_argument("--agent-skill", nargs=3, metavar=("ID", "TITLE", "DESCRIPTION"), action="append", help="Agent skill summary; repeatable")
    parser.add_argument("--claim", default=None, help="Optional signed claim JSON to include as claim_7187.json")
    parser.add_argument("--citations", default=None, help="Optional Bitmap citations JSON to include as citations.json")


def build_cell_resolution(args: argparse.Namespace) -> int:
    result = build_cell_resolution_package(
        out_dir=Path(args.out).expanduser().resolve(),
        coordinate=args.coordinate,
        base_url=args.base_url,
        controller_address=args.controller_address,
        version=args.version,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["verification"]["ok"] else 2


def verify_cell_resolution(args: argparse.Namespace) -> int:
    result = verify_cell_resolution_package(Path(args.package).expanduser().resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a Bitmap Memory Portal from a local folder")
    sub = parser.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate", help="Generate manifest.json, proof.json, agent.json, and portal.html")
    _add_agent_root_arguments(g)
    g.set_defaults(func=generate)

    v = sub.add_parser("verify", help="Verify a source folder against manifest.json")
    v.add_argument("--source", required=True, help="Source folder to verify")
    v.add_argument("--manifest", required=True, help="Path to manifest.json")
    v.set_defaults(func=verify)

    l = sub.add_parser("landing", help="Generate public project landing.html")
    l.add_argument("--out", required=True, help="Output folder")
    l.add_argument("--demo-portal", required=True, help="Relative or absolute path to demo portal.html")
    l.add_argument("--manifest-hash", required=True, help="Demo manifest hash")
    l.add_argument("--merkle-root", required=True, help="Demo Merkle root")
    l.add_argument("--files-count", required=True, type=int, help="Demo indexed file count")
    l.add_argument("--agent-name", default="Bitmap Memory Guardian", help="Agent name to display on landing page")
    l.add_argument("--agent-root-type", default="bitmap-agent-root", help="Agent root type to display on landing page")
    l.add_argument("--skills-count", default=0, type=int, help="Agent skill count to display on landing page")
    l.set_defaults(func=landing)

    p = sub.add_parser("publish", help="Package landing + demo into a static public directory")
    p.add_argument("--landing", required=True, help="Path to landing.html")
    p.add_argument("--demo-dir", required=True, help="Directory containing portal.html, manifest.json, proof.json")
    p.add_argument("--out", required=True, help="Output public directory")
    p.add_argument("--project-name", default="Bitmap Memory Portal", help="Project name for README")
    p.set_defaults(func=publish)

    a = sub.add_parser("ask", help="Build a Markdown context pack for asking an AI about a Bitmap portal")
    a.add_argument("--source", required=True, help="Source folder containing files listed in manifest.json")
    a.add_argument("--manifest", required=True, help="Path to manifest.json")
    a.add_argument("--proof", required=True, help="Path to proof.json")
    a.add_argument("--agent", required=True, help="Path to agent.json")
    a.add_argument("--question", required=True, help="Question to include in the context pack")
    a.add_argument("--out", required=True, help="Markdown output path")
    a.set_defaults(func=ask)

    cg = sub.add_parser("graph", help="Build graph.json and graph.html from one or more citations.json files")
    cg.add_argument("--citations", required=True, action="append", help="Path to citations.json; repeatable")
    cg.add_argument("--out", required=True, help="Output directory for graph.json and graph.html")
    cg.set_defaults(func=graph)

    gf = sub.add_parser(
        "graphify-checkpoint",
        help="Run safe code-only Graphify extraction and write an Organa derived-evidence checkpoint",
    )
    gf.add_argument("--source", required=True, help="Public-safe source folder to extract")
    gf.add_argument("--out", required=True, help="Output directory for graphify-out and checkpoint JSON")
    gf.set_defaults(func=graphify_checkpoint)

    b = sub.add_parser("build-package", help="One-command tool: generate demo, landing, public folder, verify_ok.json, and zip")
    _add_agent_root_arguments(b)
    b.add_argument("--project-name", default="Bitmap Agent Root Portal", help="Project name for README")
    b.add_argument("--zip-name", default="bitmap-agent-root-portal.zip", help="Zip filename written under --out")
    b.add_argument("--clean", action="store_true", default=True, help="Remove existing output folder before building")
    b.set_defaults(func=build_package)

    cr = sub.add_parser("build-cell-resolution", help="Build an Organa Cell Resolution Manifest v0.1 package")
    cr.add_argument("--out", required=True, help="Output folder for the public machine-readable package")
    cr.add_argument("--coordinate", required=True, help="Bitmap coordinate, e.g. 7187.bitmap")
    cr.add_argument("--base-url", required=True, help="Future public HTTPS base URL")
    cr.add_argument("--controller-address", required=True, help="Wallet address that will sign the controller claim")
    cr.add_argument("--version", default="0.1.0", help="Cell resolution version")
    cr.set_defaults(func=build_cell_resolution)

    cvr = sub.add_parser("verify-cell-resolution", help="Verify a generated Organa Cell Resolution package")
    cvr.add_argument("--package", required=True, help="Path to the generated package directory")
    cvr.set_defaults(func=verify_cell_resolution)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
