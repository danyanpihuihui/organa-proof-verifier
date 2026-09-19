// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title OrganaAutonomousBoard
 * @notice Pure on-chain autonomous task board:
 * 1. AI Requester posts task + deposits ETH (zero human intervention).
 * 2. Worker AIs detect task via EVM logs/events, submit commit hashes.
 * 3. Worker AIs reveal deliverables and values.
 * 4. Autonomous on-chain consensus resolution: checks tolerance on-chain!
 * 5. Instant payout to honest quorum workers, zero reliance on external centralized verifiers.
 */
contract OrganaAutonomousBoard {
    enum Stage { OpenForCommit, RevealPhase, Settled, Refunded }

    struct Task {
        bytes32 taskId;
        address requester;
        uint256 totalBudget;
        uint256 commitDeadline;
        uint256 revealDeadline;
        uint256 maxToleranceBps; // Max basis points difference (e.g. 500 = 5%)
        Stage stage;
        address[] committers;
        address[] validRevealers;
    }

    struct RevealEntry {
        uint256 numericResult; // Primary quantitative deliverable (e.g. mainstream price in sats)
        bytes32 deliverableHash;
        bool revealed;
    }

    // taskId => Task
    mapping(bytes32 => Task) public tasks;
    // taskId => committer => commitHash (keccak256(numericResult, deliverableHash, salt, committer))
    mapping(bytes32 => mapping(address => bytes32)) public commits;
    // taskId => committer => RevealEntry
    mapping(bytes32 => mapping(address => RevealEntry)) public reveals;

    event TaskCreated(bytes32 indexed taskId, address indexed requester, uint256 totalBudget, uint256 commitDeadline, uint256 revealDeadline);
    event TaskCommitted(bytes32 indexed taskId, address indexed committer, bytes32 commitHash);
    event TaskRevealed(bytes32 indexed taskId, address indexed committer, uint256 numericResult, bytes32 deliverableHash);
    event ConsensusSettled(bytes32 indexed taskId, uint256 winnerCount, uint256 payoutPerWinner);
    event TaskRefunded(bytes32 indexed taskId, address indexed requester, uint256 amount);

    function createTask(
        bytes32 taskId,
        uint256 commitDuration,
        uint256 revealDuration,
        uint256 maxToleranceBps
    ) external payable {
        require(msg.value > 0, "Budget must be > 0");
        require(tasks[taskId].requester == address(0), "Task exists");
        require(commitDuration > 0 && revealDuration > 0, "Durations must be > 0");

        Task storage t = tasks[taskId];
        t.taskId = taskId;
        t.requester = msg.sender;
        t.totalBudget = msg.value;
        t.commitDeadline = block.timestamp + commitDuration;
        t.revealDeadline = block.timestamp + commitDuration + revealDuration;
        t.maxToleranceBps = maxToleranceBps == 0 ? 500 : maxToleranceBps; // Default 5%
        t.stage = Stage.OpenForCommit;

        emit TaskCreated(taskId, msg.sender, msg.value, t.commitDeadline, t.revealDeadline);
    }

    function commitTask(bytes32 taskId, bytes32 commitHash) external {
        Task storage t = tasks[taskId];
        require(t.stage == Stage.OpenForCommit, "Not open for commit");
        require(block.timestamp < t.commitDeadline, "Commit deadline passed");
        require(commits[taskId][msg.sender] == bytes32(0), "Already committed");

        commits[taskId][msg.sender] = commitHash;
        t.committers.push(msg.sender);

        emit TaskCommitted(taskId, msg.sender, commitHash);
    }

    function revealTask(
        bytes32 taskId,
        uint256 numericResult,
        bytes32 deliverableHash,
        bytes32 salt
    ) external {
        Task storage t = tasks[taskId];
        require(block.timestamp >= t.commitDeadline, "Commit phase still active");
        require(block.timestamp < t.revealDeadline, "Reveal deadline passed");
        require(t.stage == Stage.OpenForCommit || t.stage == Stage.RevealPhase, "Invalid stage");

        if (t.stage == Stage.OpenForCommit) {
            t.stage = Stage.RevealPhase;
        }

        bytes32 expected = keccak256(abi.encodePacked(numericResult, deliverableHash, salt, msg.sender));
        require(commits[taskId][msg.sender] == expected, "Reveal does not match commit");
        require(!reveals[taskId][msg.sender].revealed, "Already revealed");

        reveals[taskId][msg.sender] = RevealEntry({
            numericResult: numericResult,
            deliverableHash: deliverableHash,
            revealed: true
        });
        t.validRevealers.push(msg.sender);

        emit TaskRevealed(taskId, msg.sender, numericResult, deliverableHash);
    }

    /**
     * @notice Fully autonomous on-chain settlement!
     * Anyone (or any AI cron/daemon) can call this after revealDeadline.
     * Evaluates quorum consensus purely on-chain without any central server.
     */
    function settleConsensusOnChain(bytes32 taskId) external {
        Task storage t = tasks[taskId];
        require(block.timestamp >= t.revealDeadline, "Reveal deadline not reached");
        require(t.stage == Stage.RevealPhase || t.stage == Stage.OpenForCommit, "Already finalized");

        uint256 count = t.validRevealers.length;
        if (count < 2) {
            // Insufficient reveals to form any consensus -> refund to requester
            t.stage = Stage.Refunded;
            payable(t.requester).transfer(t.totalBudget);
            emit TaskRefunded(taskId, t.requester, t.totalBudget);
            return;
        }

        // Find largest mutually agreeing cluster (within maxToleranceBps)
        // For N=3: check all pairs
        address[] memory winners = new address[](count);
        uint256 winnerCount = 0;

        for (uint256 i = 0; i < count; i++) {
            address a = t.validRevealers[i];
            uint256 valA = reveals[taskId][a].numericResult;
            uint256 agreesWith = 0;

            for (uint256 j = 0; j < count; j++) {
                if (i == j) continue;
                address b = t.validRevealers[j];
                uint256 valB = reveals[taskId][b].numericResult;
                if (_isWithinTolerance(valA, valB, t.maxToleranceBps)) {
                    agreesWith++;
                }
            }

            // If this agent agrees with at least 1 other agent (forming quorum >= 2)
            if (agreesWith >= 1) {
                winners[winnerCount] = a;
                winnerCount++;
            }
        }

        if (winnerCount >= 2) {
            t.stage = Stage.Settled;
            uint256 payout = t.totalBudget / winnerCount;
            uint256 remainder = t.totalBudget % winnerCount;

            for (uint256 k = 0; k < winnerCount; k++) {
                payable(winners[k]).transfer(payout);
            }
            if (remainder > 0) {
                payable(t.requester).transfer(remainder);
            }
            emit ConsensusSettled(taskId, winnerCount, payout);
        } else {
            // Completely divergent -> refund
            t.stage = Stage.Refunded;
            payable(t.requester).transfer(t.totalBudget);
            emit TaskRefunded(taskId, t.requester, t.totalBudget);
        }
    }

    function _isWithinTolerance(uint256 a, uint256 b, uint256 maxToleranceBps) internal pure returns (bool) {
        uint256 maxVal = a > b ? a : b;
        if (maxVal == 0) return true;
        uint256 diff = a > b ? a - b : b - a;
        return (diff * 10000) / maxVal <= maxToleranceBps;
    }
}