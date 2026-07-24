import json
from pathlib import Path

from bitmap_memory_portal.hallmark_audit import audit_html, build_hallmark_artifact


def test_hallmark_audit_detects_repetitive_cards_and_unqualified_metrics(tmp_path):
    html_path = tmp_path / "portal.html"
    html_path.write_text(
        """<!doctype html><html lang='en'><body>
        <h1>Agent Portal</h1>
        <div class='grid'>
          <div class='card'><div class='label'>Users</div><div class='value'>1,200</div></div>
          <div class='card'><div class='label'>Accuracy</div><div class='value'>99%</div></div>
          <div class='card'><div class='label'>Growth</div><div class='value'>42%</div></div>
          <div class='card'><div class='label'>Revenue</div><div class='value'>$10M</div></div>
        </div>
        </body></html>""",
        encoding="utf-8",
    )

    report = audit_html(html_path)

    rules = {finding["rule_id"] for finding in report["findings"]}
    assert "HLM-CARDS-001" in rules
    assert "HLM-PROOF-001" in rules
    assert report["source"]["sha256"].startswith("sha256:")
    assert report["canonical_state_mutation"] is False


def test_hallmark_audit_recognizes_evidence_language_and_builds_hashed_artifact(tmp_path):
    html_path = tmp_path / "portal.html"
    html_path.write_text(
        """<!doctype html><html lang='en'><body>
        <h1>Verified Portal</h1>
        <section><h2>Evidence</h2><p>20 files verified from manifest.json.</p></section>
        <section><h2>Limitations</h2><p>Pending timestamp; cannot verify private strategy.</p></section>
        </body></html>""",
        encoding="utf-8",
    )
    report = audit_html(html_path)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    artifact = build_hallmark_artifact(report_path)

    assert not any(x["rule_id"] == "HLM-PROOF-001" for x in report["findings"])
    assert artifact["adapter_id"] == "hallmark-audit"
    assert artifact["mode"] == "read-only-ui-audit"
    assert artifact["report"]["sha256"].startswith("sha256:")
    assert artifact["design_changes_applied"] is False
