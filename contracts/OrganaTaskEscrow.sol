// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title OrganaTaskEscrow
 * @notice Trust-minimized multi-agent escrow for Organa Protocol tasks.
 * 
 * DESIGN PRINCIPLE (Requester-Centric Fixed Budget):
 * The requester sets a single total budget (e.g. 1.0 ETH or $1).
 * The requester does NOT worry about how many AI agents are recruited under the hood.
 * If 3 agents form a verified consensus quorum, the fixed pot is divided equally
 * (e.g. 0.33 ETH each), plus any leftover dust returned or retained.
 * 
 * Flow:
 * 1. Requester calls `createTask` with msg.value (the total pot).
 * 2. Agents submit blinded commits before commitDeadline.
 * 3. Agents reveal deliverables before revealDeadline.
 * 4. Verifier executes consensus engine and calls `settleConsensus(offerHash, winners)`.
 * 5. Escrow automatically splits the total pot among the verified winners.
 */
contract OrganaTaskEscrow {
    enum TaskState { Created, CommitPhase, RevealPhase, Completed, Cancelled, Expired }
    enum RuleType { RequesterEvaluates, ConsensusQuorum }

    struct Task {
        bytes32 offerHash;
        address requester;
        uint256 totalBudget;     // Fixed total pot provided by requester (e.g. 1.0)
        uint64 commitDeadline;
        uint64 revealDeadline;
        uint8 requiredQuorum;    // e.g. 3
        RuleType ruleType;
        TaskState state;
        uint8 committedCount;
        uint8 revealedCount;
    }

    struct CommitEntry {
        bytes32 commitHash; // keccak256(abi.encodePacked(artifactHash, salt, agentAddress))
        uint64 timestamp;
    }

    struct RevealEntry {
        bytes32 artifactHash;
        bool valid;
    }

    address public immutable trustedVerifier;
    mapping(bytes32 => Task) public tasks;
    mapping(bytes32 => mapping(address => CommitEntry)) public commits;
    mapping(bytes32 => mapping(address => RevealEntry)) public reveals;
    mapping(bytes32 => address[]) public committedAgents;

    event TaskCreated(bytes32 indexed offerHash, address indexed requester, uint256 totalBudget, uint8 requiredQuorum);
    event TaskCommitted(bytes32 indexed offerHash, address indexed agent, bytes32 commitHash);
    event TaskRevealed(bytes32 indexed offerHash, address indexed agent, bytes32 artifactHash);
    event TaskSettled(bytes32 indexed offerHash, address[] winners, uint256 payoutPerWinner, uint256 totalDistributed);
    event TaskRefunded(bytes32 indexed offerHash, address indexed requester, uint256 amount);

    error TaskAlreadyExists();
    error TaskNotFound();
    error InvalidState();
    error ZeroBudget();
    error CommitDeadlinePassed();
    error RevealDeadlineNotStarted();
    error RevealDeadlinePassed();
    error InvalidRevealProof();
    error UnauthorizedVerifier();
    error NoWinnersProvided();

    modifier onlyVerifier() {
        if (msg.sender != trustedVerifier) revert UnauthorizedVerifier();
        _;
    }

    constructor(address _trustedVerifier) {
        trustedVerifier = _trustedVerifier;
    }

    /**
     * @notice Create a task escrow with fixed total budget.
     * @param offerHash Unique hash of the task offer.
     * @param requiredQuorum Expected number of agents in quorum (e.g. 3).
     * @param commitDuration Seconds for blind commit phase.
     * @param revealDuration Seconds for reveal phase.
     * @param ruleType Evaluation rule.
     */
    function createTask(
        bytes32 offerHash,
        uint8 requiredQuorum,
        uint64 commitDuration,
        uint64 revealDuration,
        RuleType ruleType
    ) external payable {
        if (tasks[offerHash].requester != address(0)) revert TaskAlreadyExists();
        if (msg.value == 0) revert ZeroBudget();

        tasks[offerHash] = Task({
            offerHash: offerHash,
            requester: msg.sender,
            totalBudget: msg.value,
            commitDeadline: uint64(block.timestamp + commitDuration),
            revealDeadline: uint64(block.timestamp + commitDuration + revealDuration),
            requiredQuorum: requiredQuorum,
            ruleType: ruleType,
            state: TaskState.CommitPhase,
            committedCount: 0,
            revealedCount: 0
        });

        emit TaskCreated(offerHash, msg.sender, msg.value, requiredQuorum);
    }

    /**
     * @notice Blindly commit task completion hash (Commit Phase).
     */
    function commitTask(bytes32 offerHash, bytes32 commitHash) external {
        Task storage t = tasks[offerHash];
        if (t.requester == address(0)) revert TaskNotFound();
        if (t.state != TaskState.CommitPhase) revert InvalidState();
        if (block.timestamp > t.commitDeadline) revert CommitDeadlinePassed();
        if (commits[offerHash][msg.sender].commitHash != bytes32(0)) revert InvalidState();

        commits[offerHash][msg.sender] = CommitEntry({
            commitHash: commitHash,
            timestamp: uint64(block.timestamp)
        });
        committedAgents[offerHash].push(msg.sender);
        t.committedCount++;

        emit TaskCommitted(offerHash, msg.sender, commitHash);
    }

    /**
     * @notice Reveal the artifact and salt (Reveal Phase).
     */
    function revealTask(bytes32 offerHash, bytes32 artifactHash, bytes32 salt) external {
        Task storage t = tasks[offerHash];
        if (t.requester == address(0)) revert TaskNotFound();
        if (block.timestamp <= t.commitDeadline) revert RevealDeadlineNotStarted();
        if (block.timestamp > t.revealDeadline) revert RevealDeadlinePassed();

        CommitEntry memory c = commits[offerHash][msg.sender];
        if (c.commitHash == bytes32(0)) revert InvalidState();

        bytes32 expected = keccak256(abi.encodePacked(artifactHash, salt, msg.sender));
        if (expected != c.commitHash) revert InvalidRevealProof();

        reveals[offerHash][msg.sender] = RevealEntry({
            artifactHash: artifactHash,
            valid: true
        });
        t.revealedCount++;

        emit TaskRevealed(offerHash, msg.sender, artifactHash);
    }

    /**
     * @notice Trustlessly split the fixed total budget among verified winners.
     * Any remainder/dust is refunded back to the requester.
     */
    function settleConsensus(
        bytes32 offerHash,
        address[] calldata winners
    ) external onlyVerifier {
        Task storage t = tasks[offerHash];
        if (t.requester == address(0)) revert TaskNotFound();
        if (t.state == TaskState.Completed || t.state == TaskState.Cancelled) revert InvalidState();
        if (winners.length == 0) revert NoWinnersProvided();

        t.state = TaskState.Completed;

        uint256 winnerCount = winners.length;
        uint256 payoutPerWinner = t.totalBudget / winnerCount;
        uint256 totalPayout = payoutPerWinner * winnerCount;
        uint256 remainder = t.totalBudget - totalPayout;

        // Distribute equal shares to all winning consensus agents
        for (uint256 i = 0; i < winnerCount; i++) {
            address payable winner = payable(winners[i]);
            (bool ok, ) = winner.call{value: payoutPerWinner}("");
            require(ok, "Transfer to winner failed");
        }

        // If integer division leaves remainder, refund dust to requester
        if (remainder > 0) {
            (bool okDust, ) = payable(t.requester).call{value: remainder}("");
            require(okDust, "Refund dust failed");
        }

        emit TaskSettled(offerHash, winners, payoutPerWinner, totalPayout);
    }

    /**
     * @notice Full refund if consensus was never achieved or deadline expired.
     */
    function refund(bytes32 offerHash) external {
        Task storage t = tasks[offerHash];
        if (t.requester == address(0)) revert TaskNotFound();
        if (t.state == TaskState.Completed || t.state == TaskState.Cancelled) revert InvalidState();
        if (block.timestamp <= t.revealDeadline) revert InvalidState();

        t.state = TaskState.Cancelled;
        uint256 amount = t.totalBudget;
        (bool ok, ) = payable(t.requester).call{value: amount}("");
        require(ok, "Refund failed");

        emit TaskRefunded(offerHash, t.requester, amount);
    }
}
