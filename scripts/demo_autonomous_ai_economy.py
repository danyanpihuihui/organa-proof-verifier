#!/usr/bin/env python3
"""Simulation of 100% Autonomous AI-to-AI On-Chain Task Economy.

Zero human intervention:
- AI Requester: detects missing data, deposits 0.0001 ETH into OrganaAutonomousBoard.
- Worker AIs (Alpha, Beta, Gamma): listen to on-chain TaskCreated event, pull data, compute, and commit hashes.
- Worker AIs: wait for reveal phase, broadcast values and proofs.
- On-chain settleConsensusOnChain: evaluates tolerance purely in EVM, pays winners instantly.
"""

import hashlib
import json
import time
from datetime import datetime, timezone

def keccak_commit(numeric_result: int, deliverable_hash: bytes, salt: bytes, committer: str) -> str:
    # Emulate EVM keccak256(abi.encodePacked(uint256, bytes32, bytes32, address))
    # We use hashlib for structural demonstration
    raw = (
        numeric_result.to_bytes(32, "big")
        + deliverable_hash
        + salt
        + bytes.fromhex(committer.lower().replace("0x", "").rjust(40, "0"))
    )
    return "0x" + hashlib.sha256(raw).hexdigest()

def run_simulation():
    print("======================================================================")
    print("      100% AUTONOMOUS AI-TO-AI ZERO-HUMAN ON-CHAIN SYSTEM DEMO")
    print("======================================================================")

    # 1. AI Requester initiates task on-chain
    ai_requester = "0x1111111111111111111111111111111111111111"
    task_id = "0x" + hashlib.sha256(b"bitmap-autonomous-audit-2026-09").hexdigest()
    total_budget_eth = 0.0001 # 1-pot model (fixed total budget)
    max_tolerance_bps = 500   # 5% max difference tolerance

    print(f"\n[AI-1: Requester Agent ({ai_requester[:10]}...)]")
    print(f"  -> Autonomous Need : Needs 30-day Bitmap mainstream price ground truth.")
    print(f"  -> Action          : Calls OrganaAutonomousBoard.createTask()")
    print(f"  -> Deposit         : {total_budget_eth} ETH locked in contract.")
    print(f"  -> Parameters      : Commit window: 60s | Reveal window: 60s | Tolerance: 5.0%")

    # 2. Worker AIs detect event & run compute
    print("\n[AI Workers: Event Listening & Independent Computation]")
    workers = [
        {"id": "AI-Worker-Alpha", "address": "0x6444533d31856f128f19d93edfbcba03aef36d0f", "algo": "Satflow+OKX densest band", "result": 7539},
        {"id": "AI-Worker-Beta",  "address": "0xa843e145f641bb47ae490bb349b0f5cf483a83a9", "algo": "Multi-source VWAP", "result": 7577}, # 0.5% difference
        {"id": "AI-Worker-Gamma", "address": "0xf93f0e6ce32cec4b0447c50a8f1bc76ea70b6676", "algo": "Hallucinative heuristic", "result": 15000}, # 98% deviation
    ]

    commits = {}
    reveals = {}

    for w in workers:
        deliverable_content = f"Series computed by {w['id']} using {w['algo']}: {w['result']} sats"
        deliv_hash = hashlib.sha256(deliverable_content.encode()).digest()
        salt = hashlib.sha256(f"salt-{w['id']}".encode()).digest()
        commit_hash = keccak_commit(w["result"], deliv_hash, salt, w["address"])

        commits[w["address"]] = commit_hash
        reveals[w["address"]] = {
            "worker": w,
            "numericResult": w["result"],
            "deliverableHash": deliv_hash,
            "salt": salt,
        }
        print(f"  * {w['id']} ({w['address'][:10]}...):")
        print(f"      Calculated Ground Truth : {w['result']} sats")
        print(f"      Submitted Commit Hash   : {commit_hash[:18]}... (content secret)")

    # 3. Reveal Phase
    print("\n[Phase 2: Decentralized Reveal Phase]")
    print("  -> Commit deadline passed. Contract enters Stage.RevealPhase.")
    for addr, rev in reveals.items():
        w = rev["worker"]
        print(f"  * {w['id']} calls revealTask(value={rev['numericResult']}, salt=...) -> Verified on-chain!")

    # 4. Pure On-Chain Quorum Consensus
    print("\n[Phase 3: Autonomous On-Chain Consensus & Payout]")
    print("  -> An external cron (or any worker AI) triggers: settleConsensusOnChain(taskId)")
    print("  -> EVM Execution:")

    # Simulating EVM _isWithinTolerance
    def is_within_tolerance(a, b, bps):
        max_val = max(a, b)
        diff = abs(a - b)
        return (diff * 10000) // max_val <= bps

    valid_workers = list(reveals.values())
    agreeing_workers = []

    for i, w1 in enumerate(valid_workers):
        agrees = 0
        for j, w2 in enumerate(valid_workers):
            if i == j:
                continue
            if is_within_tolerance(w1["numericResult"], w2["numericResult"], max_tolerance_bps):
                agrees += 1
        if agrees >= 1:
            agreeing_workers.append(w1)

    winner_count = len(agreeing_workers)
    payout_per_winner = total_budget_eth / winner_count if winner_count > 0 else 0

    print(f"      Valid Revealers        : {len(valid_workers)}")
    print(f"      Consensus Winners      : {winner_count} agents mutually agree within 5% band")
    for win in agreeing_workers:
        w = win["worker"]
        print(f"        -> WINNER: {w['id']} ({w['address']})")
        print(f"           Payout Transferred : {payout_per_winner:.6f} ETH")

    outliers = [w for w in valid_workers if w not in agreeing_workers]
    for out in outliers:
        w = out["worker"]
        print(f"        -> OUTLIER / REJECTED: {w['id']} ({w['address']}) - Deviation exceeded 5%, Zero Payout.")

    print("\n======================================================================")
    print("  ZERO HUMAN INTERVENTION: 100% AUTONOMOUS ECONOMIC AGENT CYCLE COMPLETE")
    print("======================================================================")

if __name__ == "__main__":
    run_simulation()
