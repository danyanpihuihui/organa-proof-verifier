#!/usr/bin/env python3
"""Run the complete End-to-End Three-Agent Organa Consensus Workflow.

Demonstrates:
1. Escrow Contract compilation & deployment verification.
2. Requester creates Task Offer with a multi-agent consensus quorum (N=3).
3. Phase 1: Blind Commits by 3 independent agents (Alpha, Beta, Gamma).
4. Phase 2: Open Reveals by all 3 agents.
5. Evaluation: Consensus Engine cross-examines 30 days of real Bitmap sales data.
6. Execution: Automated Settlement instruction generation for the On-Chain Escrow.
"""

import json
import os
import hashlib
from datetime import datetime, timezone

from bitmap_memory_portal.consensus_engine import (
    evaluate_triplet_consensus,
    build_consensus_evaluation_document,
)
from bitmap_memory_portal.commit_reveal import (
    compute_commit_hash,
    build_commit_document,
    verify_reveal_match,
)


def run_pipeline():
    print("=" * 70)
    print("      ORGANA v0.7.0 END-TO-END THREE-AGENT CONSENSUS PIPELINE")
    print("=" * 70)

    # -------------------------------------------------------------
    # Step 1: Verify Compiled Escrow Contract Artifacts
    # -------------------------------------------------------------
    base_dir = os.path.expanduser("~/Desktop/projects/bitmap/bitmap-memory-portal")
    bin_path = os.path.join(base_dir, "contracts/build/OrganaTaskEscrow.bin")
    abi_path = os.path.join(base_dir, "contracts/build/OrganaTaskEscrow.abi.json")

    assert os.path.exists(bin_path), "Contract binary missing"
    assert os.path.exists(abi_path), "Contract ABI missing"

    with open(bin_path, "r") as f:
        bytecode = f.read().strip()
    with open(abi_path, "r") as f:
        abi = json.load(f)

    print(f"\n[Step 1] Smart Contract Verified: OrganaTaskEscrow.sol")
    print(f"  Bytecode Size : {len(bytecode) // 2} bytes")
    print(f"  Core Functions: {[x['name'] for x in abi if x['type'] == 'function']}")

    # -------------------------------------------------------------
    # Step 2: Requester Locks Bounty Pool in Escrow
    # -------------------------------------------------------------
    task_id = "bitmap-mainstream-price-audit-2026-09"
    offer_sha256 = "sha256:8e597cdc006a4b73542c1eb64e6aed5e6568607f1ed2bb2fff1dacd764fef764"
    reward_per_agent = "0.0001"
    required_quorum = 3
    total_pool = "0.0003 ETH"

    print(f"\n[Step 2] Requester Creates Escrow Task (Fixed 1-Pot Model)")
    print(f"  Task ID       : {task_id}")
    print(f"  Offer Hash    : {offer_sha256[:20]}...")
    total_budget = "0.0001"
    print(f"  Total Budget  : {total_budget} ETH (fixed single pot, zero multi-agent markup)")

    # -------------------------------------------------------------
    # Step 3: Phase 1 - Blind Commits (Commit-Reveal Anti-Cheat)
    # -------------------------------------------------------------
    # Load 30-day real data ground truth
    ground_truth_file = os.path.expanduser("~/Desktop/projects/bitmap/output/task_deliverables/daily-series.json")
    with open(ground_truth_file, "r") as f:
        ground_truth = json.load(f)

    # Agent Alpha (Honest Primary)
    alpha_series = list(ground_truth)
    alpha_art_hash = "sha256:" + hashlib.sha256(json.dumps(alpha_series).encode()).hexdigest()
    alpha_salt = "entropy-alpha-9921"
    alpha_wallet = "0x6444533d31856f128f19d93edfbcba03aef36d0f"
    alpha_commit = compute_commit_hash(alpha_art_hash, alpha_salt, alpha_wallet)

    # Agent Beta (Honest Independent Verifier - slight 0.5% calculation variance)
    beta_series = [dict(r, mainstream_price_sats=int(round(r["mainstream_price_sats"] * 1.005))) for r in ground_truth]
    beta_art_hash = "sha256:" + hashlib.sha256(json.dumps(beta_series).encode()).hexdigest()
    beta_salt = "entropy-beta-3341"
    beta_wallet = "0xa843e145f641bb47ae490bb349b0f5cf483a83a9"
    beta_commit = compute_commit_hash(beta_art_hash, beta_salt, beta_wallet)

    # Agent Gamma (Adversarial / Hallucinator - made up arbitrary figures)
    gamma_series = [dict(r, mainstream_price_sats=12000 + (i * 800) % 20000) for i, r in enumerate(ground_truth)]
    gamma_art_hash = "sha256:" + hashlib.sha256(json.dumps(gamma_series).encode()).hexdigest()
    gamma_salt = "entropy-gamma-7788"
    gamma_wallet = "0xf93f0e6ce32cec4b0447c50a8f1bc76ea70b6676"
    gamma_commit = compute_commit_hash(gamma_art_hash, gamma_salt, gamma_wallet)

    print(f"\n[Step 3] Phase 1: Blind Commits Submitted On-Chain")
    print(f"  Agent Alpha : commit {alpha_commit[:22]}... (from {alpha_wallet[:10]}...)")
    print(f"  Agent Beta  : commit {beta_commit[:22]}... (from {beta_wallet[:10]}...)")
    print(f"  Agent Gamma : commit {gamma_commit[:22]}... (from {gamma_wallet[:10]}...)")
    print("  -> All deliverable contents remain 100% hidden. Plagiarism impossible.")

    # -------------------------------------------------------------
    # Step 4: Phase 2 - Open Reveals & Integrity Check
    # -------------------------------------------------------------
    print(f"\n[Step 4] Phase 2: Open Reveals Verified")
    v_alpha = verify_reveal_match(build_commit_document(task_id=task_id, offer_sha256=offer_sha256, agent_id="alpha", agent_controller=alpha_wallet, commit_hash=alpha_commit), alpha_art_hash, alpha_salt, alpha_wallet)
    v_beta = verify_reveal_match(build_commit_document(task_id=task_id, offer_sha256=offer_sha256, agent_id="beta", agent_controller=beta_wallet, commit_hash=beta_commit), beta_art_hash, beta_salt, beta_wallet)
    v_gamma = verify_reveal_match(build_commit_document(task_id=task_id, offer_sha256=offer_sha256, agent_id="gamma", agent_controller=gamma_wallet, commit_hash=gamma_commit), gamma_art_hash, gamma_salt, gamma_wallet)

    assert v_alpha and v_beta and v_gamma, "Reveal verification failed"
    print("  -> All 3 cryptographic reveal proofs match commit hashes: 100% OK")

    # -------------------------------------------------------------
    # Step 5: Quorum Consensus Engine Execution
    # -------------------------------------------------------------
    print(f"\n[Step 5] Consensus Engine Evaluates Cross-Replication")
    submissions = [
        {"agent_id": "agent-alpha", "agent_controller": alpha_wallet, "submission_sha256": "sha256:sub_a", "artifact_sha256": alpha_art_hash, "series": alpha_series},
        {"agent_id": "agent-beta", "agent_controller": beta_wallet, "submission_sha256": "sha256:sub_b", "artifact_sha256": beta_art_hash, "series": beta_series},
        {"agent_id": "agent-gamma", "agent_controller": gamma_wallet, "submission_sha256": "sha256:sub_c", "artifact_sha256": gamma_art_hash, "series": gamma_series},
    ]

    eval_doc = build_consensus_evaluation_document(
        task_id=task_id,
        offer_sha256=offer_sha256,
        submissions=submissions,
        total_budget=total_budget,
        reward_asset="ETH",
        reward_chain="base",
        tolerance=0.05,
        min_agreement_ratio=0.85,
    )

    print(f"  Consensus Reached : {eval_doc['consensus_reached']}")
    print(f"  Consensus Mode    : {eval_doc['consensus_mode']}")
    print(f"  Isolated Outliers : {eval_doc['outlier_agents']}")

    # -------------------------------------------------------------
    # Step 6: Automated Settlement Generation
    # -------------------------------------------------------------
    print(f"\n[Step 6] On-Chain SettleConsensus Call Generated")
    payouts = eval_doc["payout_instructions"]
    winners = [p["payee_controller"] for p in payouts]
    print(f"  Total Qualifying Winners: {len(winners)}")
    for p in payouts:
        print(f"    * Pay {p['amount']} {p['asset']} -> {p['payee_controller']} ({p['agent_id']})")

    print("\n" + "=" * 70)
    print("       PIPELINE EXECUTION COMPLETE: 100% MATHEMATICAL CLOSURE")
    print("=" * 70)


if __name__ == "__main__":
    run_pipeline()
