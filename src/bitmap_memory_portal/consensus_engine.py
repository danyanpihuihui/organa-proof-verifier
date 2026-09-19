"""Organa Consensus Engine: Multi-Agent Replication & Quorum Settlement.

Why this exists
----------------
In single-worker/single-evaluator task architectures, the worker faces credit/rug-pull
risk (the requester can take work without paying), and the requester faces hallucination/
sybil risk (the worker can submit hallucinated or low-effort slop).

The Consensus Engine shifts verification from subjective human judgment to
deterministic mathematical convergence:
- Multiple independent agents (typically 3) execute the identical task specification.
- Their independent deliverables (e.g. daily-series.json) are cross-evaluated.
- If their outputs converge within an objective tolerance band (e.g. +/-5%), the result
  is proven as ground truth.
- All converging agents simultaneously receive payout from the escrow pool.
- Outliers (hallucinations, fabrications, or malicious agents) are isolated and excluded.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


CONSENSUS_EVALUATION_SCHEMA = "organa-consensus-evaluation-v0.1"


def compute_series_agreement(
    series_a: Sequence[Mapping[str, Any]],
    series_b: Sequence[Mapping[str, Any]],
    *,
    key_field: str = "date",
    value_field: str = "mainstream_price_sats",
    tolerance: float = 0.05,
) -> Dict[str, Any]:
    """Compute agreement metrics between two independent time series.

    Returns:
        Dict with total_keys, matched_keys, agreement_ratio, mean_divergence, details.
    """
    map_a = {item.get(key_field): item.get(value_field) for item in series_a if key_field in item}
    map_b = {item.get(key_field): item.get(value_field) for item in series_b if key_field in item}

    common_keys = sorted(set(map_a.keys()) & set(map_b.keys()))
    all_keys = sorted(set(map_a.keys()) | set(map_b.keys()))

    if not all_keys:
        return {
            "total_keys": 0,
            "common_keys": 0,
            "matched_keys": 0,
            "agreement_ratio": 0.0,
            "mean_divergence": 1.0,
        }

    matched = 0
    divergences = []

    for k in common_keys:
        va = map_a[k]
        vb = map_b[k]

        # Both None or both zero
        if va is None and vb is None:
            matched += 1
            divergences.append(0.0)
            continue
        if va is None or vb is None:
            divergences.append(1.0)
            continue

        try:
            fa, fb = float(va), float(vb)
        except (ValueError, TypeError):
            if va == vb:
                matched += 1
                divergences.append(0.0)
            else:
                divergences.append(1.0)
            continue

        if fa == 0.0 and fb == 0.0:
            matched += 1
            divergences.append(0.0)
            continue

        denom = max(abs(fa), abs(fb))
        diff = abs(fa - fb) / denom if denom > 0 else 0.0
        divergences.append(diff)

        if diff <= tolerance:
            matched += 1

    agreement_ratio = matched / len(all_keys) if all_keys else 0.0
    mean_div = sum(divergences) / len(divergences) if divergences else 1.0

    return {
        "total_keys": len(all_keys),
        "common_keys": len(common_keys),
        "matched_keys": matched,
        "agreement_ratio": round(agreement_ratio, 4),
        "mean_divergence": round(mean_div, 4),
    }


def evaluate_triplet_consensus(
    submissions_data: Sequence[Mapping[str, Any]],
    *,
    key_field: str = "date",
    value_field: str = "mainstream_price_sats",
    tolerance: float = 0.05,
    min_agreement_ratio: float = 0.85,
) -> Dict[str, Any]:
    """Evaluate 3 independent submissions for consensus.

    Each item in submissions_data must contain:
      - agent_id: str
      - agent_controller: str
      - submission_sha256: str
      - artifact_sha256: str
      - series: Sequence[Mapping[str, Any]]
    """
    n = len(submissions_data)
    if n < 2:
        return {
            "consensus_reached": False,
            "consensus_mode": "insufficient_submissions",
            "rewarded_agents": [],
            "outlier_agents": [s["agent_id"] for s in submissions_data],
            "pairwise_matrix": {},
        }

    # Compute pairwise agreements
    pairs: Dict[Tuple[int, int], Dict[str, Any]] = {}
    for i in range(n):
        for j in range(i + 1, n):
            res = compute_series_agreement(
                submissions_data[i]["series"],
                submissions_data[j]["series"],
                key_field=key_field,
                value_field=value_field,
                tolerance=tolerance,
            )
            pairs[(i, j)] = res

    # Check pairwise consensus
    agreed_pairs = set()
    for (i, j), res in pairs.items():
        if res["agreement_ratio"] >= min_agreement_ratio:
            agreed_pairs.add((i, j))
            agreed_pairs.add((j, i))

    pairwise_readable = {
        f"{submissions_data[i]['agent_id']}_vs_{submissions_data[j]['agent_id']}": res
        for (i, j), res in pairs.items()
    }

    # Scenario 1: All 3 agree with each other (Full unanimous consensus)
    if n == 3 and len(agreed_pairs) == 6:
        return {
            "consensus_reached": True,
            "consensus_mode": "full_unanimous",
            "rewarded_agents": [
                {
                    "agent_id": s["agent_id"],
                    "agent_controller": s["agent_controller"],
                    "submission_sha256": s["submission_sha256"],
                    "artifact_sha256": s["artifact_sha256"],
                    "role": "consensus_co_discoverer",
                }
                for s in submissions_data
            ],
            "outlier_agents": [],
            "pairwise_matrix": pairwise_readable,
        }

    # Scenario 2: Majority agreement (2 agree, 1 is outlier)
    matched_indices = set()
    for i in range(n):
        partner_count = sum(1 for j in range(n) if (i, j) in agreed_pairs)
        if partner_count >= 1:
            matched_indices.add(i)

    if len(matched_indices) >= 2:
        rewarded = [
            {
                "agent_id": submissions_data[idx]["agent_id"],
                "agent_controller": submissions_data[idx]["agent_controller"],
                "submission_sha256": submissions_data[idx]["submission_sha256"],
                "artifact_sha256": submissions_data[idx]["artifact_sha256"],
                "role": "quorum_consensus_winner",
            }
            for idx in sorted(matched_indices)
        ]
        outliers = [
            submissions_data[idx]["agent_id"]
            for idx in range(n)
            if idx not in matched_indices
        ]
        return {
            "consensus_reached": True,
            "consensus_mode": "quorum_majority",
            "rewarded_agents": rewarded,
            "outlier_agents": outliers,
            "pairwise_matrix": pairwise_readable,
        }

    # Scenario 3: Complete divergence
    return {
        "consensus_reached": False,
        "consensus_mode": "divergent_no_consensus",
        "rewarded_agents": [],
        "outlier_agents": [s["agent_id"] for s in submissions_data],
        "pairwise_matrix": pairwise_readable,
    }


def build_consensus_evaluation_document(
    *,
    task_id: str,
    offer_sha256: str,
    submissions: Sequence[Mapping[str, Any]],
    total_budget: Optional[str] = None,
    reward_per_agent: Optional[str] = None,
    reward_asset: str = "ETH",
    reward_chain: str = "base",
    key_field: str = "date",
    value_field: str = "mainstream_price_sats",
    tolerance: float = 0.05,
    min_agreement_ratio: float = 0.85,
    evaluated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build a complete machine-readable Organa Consensus Evaluation Document.

    Budget policy:
    If `total_budget` is given (e.g. "0.0001"), it is split equally among all
    verified winning agents. If `reward_per_agent` is explicitly provided, it is used directly.
    """
    eval_time = (evaluated_at or datetime.now(timezone.utc)).isoformat()
    if not eval_time.endswith("Z") and not ("+" in eval_time[10:] or "-" in eval_time[10:]):
        eval_time += "Z"

    consensus_res = evaluate_triplet_consensus(
        submissions,
        key_field=key_field,
        value_field=value_field,
        tolerance=tolerance,
        min_agreement_ratio=min_agreement_ratio,
    )

    rewarded = consensus_res.get("rewarded_agents", [])
    winner_count = len(rewarded)

    # Calculate payout per agent
    payout_instructions = []
    if consensus_res["consensus_reached"] and winner_count > 0:
        if total_budget is not None:
            try:
                tot = float(total_budget)
                share = f"{tot / winner_count:.8f}".rstrip("0").rstrip(".")
            except (ValueError, TypeError):
                share = total_budget
        else:
            share = reward_per_agent or "0"

        for ag in rewarded:
            payout_instructions.append({
                "payee_controller": ag["agent_controller"],
                "agent_id": ag["agent_id"],
                "amount": share,
                "asset": reward_asset,
                "chain": reward_chain,
                "reason": f"consensus_verified_{consensus_res['consensus_mode']}",
            })

    doc = {
        "schema_version": CONSENSUS_EVALUATION_SCHEMA,
        "evaluation_id": f"eval-{task_id}-{hashlib.sha256(eval_time.encode()).hexdigest()[:12]}",
        "task_id": task_id,
        "offer_sha256": offer_sha256,
        "evaluated_at_utc": eval_time,
        "metric_spec": {
            "type": "series_tolerance_band",
            "key_field": key_field,
            "value_field": value_field,
            "tolerance": tolerance,
            "min_agreement_ratio": min_agreement_ratio,
        },
        "submissions_evaluated": [
            {
                "agent_id": s["agent_id"],
                "agent_controller": s["agent_controller"],
                "submission_sha256": s["submission_sha256"],
                "artifact_sha256": s["artifact_sha256"],
            }
            for s in submissions
        ],
        "consensus_reached": consensus_res["consensus_reached"],
        "consensus_mode": consensus_res["consensus_mode"],
        "outlier_agents": consensus_res["outlier_agents"],
        "pairwise_metrics": consensus_res["pairwise_matrix"],
        "payout_instructions": payout_instructions,
    }

    # Canonical hash of the evaluation report
    doc_bytes = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    doc["evaluation_sha256"] = "sha256:" + hashlib.sha256(doc_bytes).hexdigest()

    return doc
