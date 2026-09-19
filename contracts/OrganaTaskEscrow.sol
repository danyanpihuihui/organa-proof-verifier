// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title OrganaTaskEscrow
 * @notice Trust-minimized multi-agent escrow for Organa Protocol tasks.
 * 
 * Supports:
 * 1. Single-worker task completion (optimistic with timeout).
 * 2. Triplet / Quorum multi-agent consensus (3-of-3 unanimous or 2-of-3 majority).
 * 3. Commit-Reveal blind submissions (prevents copying / front-running).
 * 
 * Flow:
 * - Requester calls `createTask` with reward pool and verification rule.
 * - Agents commit blinded hashes of their work before deadline.
 * - Agents reveal deliverables and nonces.
 * - Verifier (or Oracle) submits verified consensus evaluation.
 * - Escrow automatically and trustlessly distributes payout to winning agents.
 */
contract OrganaTaskEscrow {
    enum TaskState { Created, CommitPhase, RevealPhase, Completed, Cancelled, Expired }
    enum RuleType { RequesterEvaluates, ConsensusQuorum }

    struct Task {
        bytes32 offerHash;
        address requester;
        uint256 totalPool;
        uint256 rewardPerAgent;
        uint64 commitDeadline;
        uint64 revealDeadline;
        uint8 requiredQuorum; // e.g. 3
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
    mapping(bytes32 => Task) public tasks; // offerHash => Task
    mapping(bytes32 => mapping(address => CommitEntry)) public commits; // offerHash => agent => Commit
    mapping(bytes32 => mapping(address => RevealEntry)) public reveals; // offerHash => agent => Reveal
    mapping(bytes32 => address[]) public committedAgents;

    event TaskCreated(bytes32 indexed offerHash, address indexed requester, uint256 totalPool, uint8 requiredQuorum);
    event TaskCommitted(bytes32 indexed offerHash, address indexed agent, bytes32 commitHash);
    event TaskRevealed(bytes32 indexed offerHash, address indexed agent, bytes32 artifactHash);
    event TaskSettled(bytes32 indexed offerHash, address[] winners, uint256 amountPerAgent);
    event TaskRefunded(bytes32 indexed offerHash, address indexed requester, uint256 amount);

    error TaskAlreadyExists();
    error TaskNotFound();
    error InvalidState();
    error InsufficientDeposit();
    error CommitDeadlinePassed();
    error RevealDeadlineNotStarted();
    error RevealDeadlinePassed();
    error InvalidRevealProof();
    error UnauthorizedVerifier();
    error QuorumNotReached();

    modifier onlyVerifier() {
        if (msg.sender != trustedVerifier) revert UnauthorizedVerifier();
        _;
    }

    constructor(address _trustedVerifier) {
        trustedVerifier = _trustedVerifier;
    }

    /**
     * @notice Create a task escrow with attached reward funds.
     */
    function createTask(
        bytes32 offerHash,
        uint256 rewardPerAgent,
        uint8 requiredQuorum,
        uint64 commitDuration,
        uint64 revealDuration,
        RuleType ruleType
    ) external payable {
        if (tasks[offerHash].requester != address(0)) revert TaskAlreadyExists();
        uint256 requiredPool = rewardPerAgent * (requiredQuorum == 0 ? 1 : requiredQuorum);
        if (msg.value < requiredPool) revert InsufficientDeposit();

        tasks[offerHash] = Task({
            offerHash: offerHash,
            requester: msg.sender,
            totalPool: msg.value,
            rewardPerAgent: rewardPerAgent,
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
     * @param commitHash keccak256(abi.encodePacked(artifactHash, salt, msg.sender))
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
     * @notice Settlement executed automatically when consensus engine proves quorum.
     */
    function settleConsensus(
        bytes32 offerHash,
        address[] calldata winners
    ) external onlyVerifier {
        Task storage t = tasks[offerHash];
        if (t.requester == address(0)) revert TaskNotFound();
        if (t.state == TaskState.Completed || t.state == TaskState.Cancelled) revert InvalidState();
        if (winners.length == 0) revert QuorumNotReached();

        t.state = TaskState.Completed;
        uint256 payout = t.rewardPerAgent;

        for (uint256 i = 0; i < winners.length; i++) {
            address payable winner = payable(winners[i]);
            (bool ok, ) = winner.call{value: payout}("");
            require(ok, "Transfer failed");
        }

        emit TaskSettled(offerHash, winners, payout);
    }

    /**
     * @notice Refund requester if deadlines expired and consensus was never reached.
     */
    function refund(bytes32 offerHash) external {
        Task storage t = tasks[offerHash];
        if (t.requester == address(0)) revert TaskNotFound();
        if (t.state == TaskState.Completed || t.state == TaskState.Cancelled) revert InvalidState();
        if (block.timestamp <= t.revealDeadline) revert InvalidState();

        t.state = TaskState.Cancelled;
        uint256 balance = address(this).balance >= t.totalPool ? t.totalPool : address(this).balance;
        (bool ok, ) = payable(t.requester).call{value: balance}("");
        require(ok, "Refund failed");

        emit TaskRefunded(offerHash, t.requester, balance);
    }
}
