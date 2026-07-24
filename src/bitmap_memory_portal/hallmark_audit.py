from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List


class _AuditParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tag_counts: Counter[str] = Counter()
        self.class_counts: Counter[str] = Counter()
        self.inline_style_count = 0
        self.lang = ""
        self.text_parts: List[str] = []
        self.heading_counts: Counter[str] = Counter()
        self._heading: str | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        self.tag_counts[tag] += 1
        attr_map = dict(attrs)
        if tag == "html":
            self.lang = attr_map.get("lang", "")
        if attr_map.get("style"):
            self.inline_style_count += 1
        for class_name in (attr_map.get("class") or "").split():
            self.class_counts[class_name] += 1
        if tag in {"h1", "h2", "h3"}:
            self._heading = tag

    def handle_endtag(self, tag: str) -> None:
        if self._heading == tag:
            self._heading = None

    def handle_data(self, data: str) -> None:
        clean = " ".join(data.split())
        if clean:
            self.text_parts.append(clean)
            if self._heading:
                self.heading_counts[self._heading] += 1


def _record(path: Path) -> Dict[str, str]:
    resolved = Path(path).expanduser().resolve()
    return {
        "path": str(resolved),
        "sha256": "sha256:" + hashlib.sha256(resolved.read_bytes()).hexdigest(),
    }


def _finding(rule_id: str, severity: str, category: str, title: str, evidence: Dict, recommendation: str) -> Dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def audit_html(path: Path) -> Dict:
    source = Path(path).expanduser().resolve()
    raw = source.read_text(encoding="utf-8")
    parser = _AuditParser()
    parser.feed(raw)
    text = " ".join(parser.text_parts)
    findings: List[Dict] = []

    card_count = parser.class_counts["card"] + parser.class_counts["metric"] + parser.class_counts["feature"]
    grid_count = parser.class_counts["grid"] + parser.class_counts["metric-grid"] + parser.class_counts["feature-grid"]
    if card_count >= 4:
        findings.append(_finding(
            "HLM-CARDS-001", "medium", "visual",
            "Repetitive card-grid composition dominates the page",
            {"card_like_elements": card_count, "grid_like_elements": grid_count},
            "Group related evidence into fewer semantic modules; reserve cards for genuinely comparable items.",
        ))

    metric_pattern = re.compile(r"(?:\b\d{2,}(?:,\d{3})*\b|\b\d+(?:\.\d+)?%|[$€£]\s?\d+(?:\.\d+)?[KMB]?)", re.I)
    metric_hits = metric_pattern.findall(text)
    evidence_terms = re.findall(r"\b(?:source|manifest|hash|sha-?256|verified|pending|cannot verify|evidence|proof|audit|timestamp)\b", text, re.I)
    if len(metric_hits) >= 3 and not evidence_terms:
        findings.append(_finding(
            "HLM-PROOF-001", "high", "content",
            "Metrics are presented without visible source or verification qualifiers",
            {"metric_like_values": metric_hits[:12], "evidence_terms_found": 0},
            "Attach source, as-of date, verification status, and limitation text to every externally meaningful metric.",
        ))

    if parser.inline_style_count >= 8:
        findings.append(_finding(
            "HLM-TOKENS-001", "low", "maintainability",
            "Repeated inline styles weaken design-token consistency",
            {"inline_style_attributes": parser.inline_style_count},
            "Move repeated spacing and color declarations into named tokens or utility classes.",
        ))

    section_count = parser.tag_counts["section"]
    h2_count = parser.heading_counts["h2"]
    if section_count >= 10:
        findings.append(_finding(
            "HLM-HIERARCHY-001", "medium", "ux",
            "Long single-page hierarchy lacks a progressive overview",
            {"sections": section_count, "h2_headings": h2_count},
            "Add an executive summary/status strip and collapsible or navigable section groups before detailed evidence.",
        ))

    if parser.lang.lower().startswith("en") and re.search(r"[\u4e00-\u9fff]", text):
        findings.append(_finding(
            "HLM-A11Y-001", "low", "accessibility",
            "Document language does not match mixed Chinese content",
            {"html_lang": parser.lang, "contains_cjk": True},
            "Use the dominant language or mark language changes on mixed-language regions.",
        ))

    if "@media" not in raw:
        findings.append(_finding(
            "HLM-RESPONSIVE-001", "medium", "responsive",
            "No responsive media rule detected",
            {"media_queries": 0},
            "Define narrow-screen behavior for grids, long hashes, navigation, and file rows.",
        ))

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: (severity_order[item["severity"]], item["rule_id"]))
    counts = Counter(item["severity"] for item in findings)
    return {
        "report_type": "hallmark-read-only-ui-audit",
        "ruleset_version": "organa-hallmark-subset-v1",
        "source": _record(source),
        "inventory": {
            "sections": section_count,
            "card_like_elements": card_count,
            "grid_like_elements": grid_count,
            "inline_style_attributes": parser.inline_style_count,
            "metric_like_values": len(metric_hits),
            "evidence_qualifier_terms": len(evidence_terms),
            "document_language": parser.lang,
        },
        "findings": findings,
        "summary": {
            "total": len(findings),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
        },
        "canonical_state_mutation": False,
        "design_changes_applied": False,
    }


def build_hallmark_artifact(report_path: Path) -> Dict:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    return {
        "artifact_type": "organa-cell-adapter-result",
        "adapter_id": "hallmark-audit",
        "adapter_version": report.get("ruleset_version", "organa-hallmark-subset-v1"),
        "capability_type": "ui-design-audit",
        "mode": "read-only-ui-audit",
        "report": _record(report_path),
        "finding_summary": report.get("summary") or {},
        "warnings": ["Findings are advisory and do not change the portal automatically."],
        "canonical_state_mutation": False,
        "design_changes_applied": False,
        "approval_required_for_design_changes": True,
    }
