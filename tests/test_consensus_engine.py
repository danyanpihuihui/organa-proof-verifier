"""Tests for Organa Consensus Engine (Three-Agent Quorum Verification)."""

from datetime import datetime, timezone
import pytest

from bitmap_memory_portal.consensus_engine import (
    CONSENSUS_EVALUATION_SCHEMA,
    compute_series_agreement,
    evaluate_triplet_consensus,
    build_consensus_evaluation_document,
)


def _make_series(base_prices):
    return [
        {"date": f"2026-09-{i+1:02d}", "mainstream_price_sats": p}
        for i, p in enumerate(base_prices)
    ]


def test_series_agreement_identical():
    prices = [5000, 6000, 7500, 8000, 5200]
    sa = _make_series(prices)
    sb = _make_series(prices)
    res = compute_series_agreement(sa, sb, tolerance=0.05)
    assert res["total_keys"] == 5
    assert res["matched_keys"] == 5
    assert res["agreement_ratio"] == 1.0
    assert res["mean_divergence"] == 0.0


def test_series_agreement_within_tolerance():
    sa = _make_series([10000, 10000, 10000])
    sb = _make_series([10200, 9800, 10400])  # all within 4% (< 5%)
    res = compute_series_agreement(sa, sb, tolerance=0.05)
    assert res["matched_keys"] == 3
    assert res["agreement_ratio"] == 1.0


def test_series_agreement_exceeding_tolerance():
    sa = _make_series([10000, 10000, 10000])
    sb = _make_series([12000, 10000, 10000])  # first is 20% off
    res = compute_series_agreement(sa, sb, tolerance=0.05)
    assert res["matched_keys"] == 2
    assert pytest.approx(res["agreement_ratio"], 0.01) == 0.67


def test_triplet_consensus_full_unanimous():
    base = [5000, 5200, 5100, 4900, 5300]
    sub1 = {
        "agent_id": "agent-alpha",
        "agent_controller": "0x1111111111111111111111111111111111111111",
        "submission_sha256": "sha256:1111",
        "artifact_sha256": "sha256:aaaa",
        "series": _make_series(base),
    }
    sub2 = {
        "agent_id": "agent-beta",
        "agent_controller": "0x2222222222222222222222222222222222222222",
        "submission_sha256": "sha256:2222",
        "artifact_sha256": "sha256:bbbb",
        "series": _make_series([p * 1.01 for p in base]),  # 1% variance
    }
    sub3 = {
        "agent_id": "agent-gamma",
        "agent_controller": "0x3333333333333333333333333333333333333333",
        "submission_sha256": "sha256:3333",
        "artifact_sha256": "sha256:cccc",
        "series": _make_series([p * 0.99 for p in base]),  # 1% variance
    }

    res = evaluate_triplet_consensus([sub1, sub2, sub3], tolerance=0.05, min_agreement_ratio=0.8)
    assert res["consensus_reached"] is True
    assert res["consensus_mode"] == "full_unanimous"
    assert len(res["rewarded_agents"]) == 3
    assert len(res["outlier_agents"]) == 0


def test_triplet_consensus_quorum_majority_excludes_hallucinating_outlier():
    base = [5000, 5200, 5100, 4900, 5300]
    honest_1 = {
        "agent_id": "agent-honest-1",
        "agent_controller": "0x1111111111111111111111111111111111111111",
        "submission_sha256": "sha256:1111",
        "artifact_sha256": "sha256:aaaa",
        "series": _make_series(base),
    }
    honest_2 = {
        "agent_id": "agent-honest-2",
        "agent_controller": "0x2222222222222222222222222222222222222222",
        "submission_sha256": "sha256:2222",
        "artifact_sha256": "sha256:bbbb",
        "series": _make_series([p * 1.01 for p in base]),
    }
    # Fake / Hallucinating agent who made up completely wrong numbers
    hallucinator = {
        "agent_id": "agent-hallucinating",
        "agent_controller": "0x9999999999999999999999999999999999999999",
        "submission_sha256": "sha256:9999",
        "artifact_sha256": "sha256:xxxx",
        "series": _make_series([19999, 25000, 31000, 18000, 45000]),
    }

    res = evaluate_triplet_consensus([honest_1, honest_2, hallucinator], tolerance=0.05, min_agreement_ratio=0.8)
    assert res["consensus_reached"] is True
    assert res["consensus_mode"] == "quorum_majority"
    rewarded_ids = [r["agent_id"] for r in res["rewarded_agents"]]
    assert "agent-honest-1" in rewarded_ids
    assert "agent-honest-2" in rewarded_ids
    assert "agent-hallucinating" not in rewarded_ids
    assert res["outlier_agents"] == ["agent-hallucinating"]


def test_triplet_consensus_divergent_all_fail():
    sub1 = {
        "agent_id": "a1", "agent_controller": "0x1", "submission_sha256": "s1", "artifact_sha256": "a1",
        "series": _make_series([1000, 1000, 1000]),
    }
    sub2 = {
        "agent_id": "a2", "agent_controller": "0x2", "submission_sha256": "s2", "artifact_sha256": "a2",
        "series": _make_series([5000, 5000, 5000]),
    }
    sub3 = {
        "agent_id": "a3", "agent_controller": "0x3", "submission_sha256": "s3", "artifact_sha256": "a3",
        "series": _make_series([9000, 9000, 9000]),
    }
    res = evaluate_triplet_consensus([sub1, sub2, sub3], tolerance=0.05, min_agreement_ratio=0.8)
    assert res["consensus_reached"] is False
    assert res["consensus_mode"] == "divergent_no_consensus"
    assert len(res["rewarded_agents"]) == 0
    assert len(res["outlier_agents"]) == 3


def test_build_consensus_evaluation_document():
    base = [5000, 5200, 5100]
    subs = [
        {"agent_id": f"agent-{i}", "agent_controller": f"0x{i}abc", "submission_sha256": f"s{i}", "artifact_sha256": f"a{i}", "series": _make_series(base)}
        for i in range(1, 4)
    ]
    # Test Fixed Total Budget Splitting: Total = 1.0 ETH, 3 agents -> 0.33333333 ETH each
    doc = build_consensus_evaluation_document(
        task_id="bitmap-mainstream-price-audit-2026-09",
        offer_sha256="sha256:testoffer",
        submissions=subs,
        total_budget="1.0",
        reward_asset="ETH",
        reward_chain="base",
        tolerance=0.05,
        min_agreement_ratio=0.85,
    )
    assert doc["schema_version"] == CONSENSUS_EVALUATION_SCHEMA
    assert doc["consensus_reached"] is True
    assert doc["consensus_mode"] == "full_unanimous"
    assert len(doc["payout_instructions"]) == 3
    assert all(p["amount"] == "0.33333333" for p in doc["payout_instructions"])
    assert doc["evaluation_sha256"].startswith("sha256:")
