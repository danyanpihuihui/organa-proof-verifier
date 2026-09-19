"""Tests for Commit-Reveal anti-plagiarism mechanism."""

from bitmap_memory_portal.commit_reveal import (
    COMMIT_SCHEMA,
    compute_commit_hash,
    build_commit_document,
    verify_reveal_match,
)


def test_commit_hash_deterministic():
    h1 = compute_commit_hash("sha256:abcd", "salt123", "0x1111111111111111111111111111111111111111")
    h2 = compute_commit_hash("sha256:abcd", "salt123", "0x1111111111111111111111111111111111111111")
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_commit_hash_binds_agent_controller():
    # Different agent attempting to submit the same artifact with the same salt gets a different commit hash
    h1 = compute_commit_hash("sha256:abcd", "salt123", "0x1111111111111111111111111111111111111111")
    h2 = compute_commit_hash("sha256:abcd", "salt123", "0x2222222222222222222222222222222222222222")
    assert h1 != h2


def test_reveal_verification_success():
    art = "sha256:artifact999"
    salt = "secret-entropy-42"
    ctrl = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"
    commit_hash = compute_commit_hash(art, salt, ctrl)

    doc = build_commit_document(
        task_id="test-task",
        offer_sha256="sha256:offer123",
        agent_id="agent-1",
        agent_controller=ctrl,
        commit_hash=commit_hash,
    )
    assert doc["schema_version"] == COMMIT_SCHEMA
    assert verify_reveal_match(doc, art, salt, ctrl) is True


def test_reveal_verification_fails_on_tampering():
    art = "sha256:artifact999"
    salt = "secret-entropy-42"
    ctrl = "0x1111111111111111111111111111111111111111"
    commit_hash = compute_commit_hash(art, salt, ctrl)

    doc = build_commit_document(
        task_id="test-task",
        offer_sha256="sha256:offer123",
        agent_id="agent-1",
        agent_controller=ctrl,
        commit_hash=commit_hash,
    )
    # Different artifact revealed
    assert verify_reveal_match(doc, "sha256:modified_artifact", salt, ctrl) is False
    # Different salt
    assert verify_reveal_match(doc, art, "wrong-salt", ctrl) is False
    # Impersonator attempting to claim the commit
    assert verify_reveal_match(doc, art, salt, "0x2222222222222222222222222222222222222222") is False
