import json
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.error import URLError

import pytest

from bitmap_memory_portal.signed_snapshot import verify_signed_organa_snapshot


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SIGNED_SNAPSHOT = PROJECT_ROOT / "output" / "organa-cell-7187-github-pages"
TRUSTED_MANIFEST_HASH = "sha256:e1a36acbb702b46fc50bcb9f0f20b754ff813fd6198c88cccae2a33762c453ce"


def _copy_snapshot(tmp_path: Path) -> Path:
    destination = tmp_path / "snapshot"
    shutil.copytree(SIGNED_SNAPSHOT, destination, ignore=shutil.ignore_patterns(".git"))
    return destination


def test_frozen_v01_signed_snapshot_verifies_against_trusted_manifest_hash():
    result = verify_signed_organa_snapshot(
        SIGNED_SNAPSHOT,
        trusted_manifest_hash=TRUSTED_MANIFEST_HASH,
    )

    assert result["ok"] is True
    assert result["manifest_sha256"] == TRUSTED_MANIFEST_HASH
    assert result["coordinate"] == "7187.bitmap"
    assert result["version"] == "0.1.0"
    assert result["signature_valid"] is True
    assert result["errors"] == []


@pytest.mark.parametrize(
    "relative_path",
    [
        "organa-cell.json",
        "signature-request.json",
        "controller-claim.json",
        ".well-known/organa.json",
        "agent-registry.json",
    ],
)
def test_signed_snapshot_fails_closed_on_any_trusted_file_byte_tampering(tmp_path, relative_path):
    snapshot = _copy_snapshot(tmp_path)
    target = snapshot / relative_path
    target.write_bytes(target.read_bytes() + b" ")

    result = verify_signed_organa_snapshot(
        snapshot,
        trusted_manifest_hash=TRUSTED_MANIFEST_HASH,
    )

    assert result["ok"] is False
    assert result["errors"]


def test_signed_snapshot_rejects_claim_that_does_not_match_signature_request(tmp_path):
    snapshot = _copy_snapshot(tmp_path)
    claim_path = snapshot / "controller-claim.json"
    claim = json.loads(claim_path.read_text(encoding="utf-8"))
    claim["message"] += "tampered"
    claim_path.write_text(json.dumps(claim), encoding="utf-8")
    discovery_path = snapshot / ".well-known" / "organa.json"
    discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
    import hashlib
    discovery["controller_claim"]["signed_claim_sha256"] = "sha256:" + hashlib.sha256(claim_path.read_bytes()).hexdigest()
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")

    result = verify_signed_organa_snapshot(snapshot)

    assert result["ok"] is False
    assert any("claim" in error.lower() or "signature" in error.lower() for error in result["errors"])


def test_signed_snapshot_rejects_unsafe_manifest_resource_path_without_reading_outside(tmp_path):
    snapshot = _copy_snapshot(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret": true}', encoding="utf-8")
    manifest_path = snapshot / "organa-cell.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resources"][0]["path"] = "../outside.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = verify_signed_organa_snapshot(snapshot)

    assert result["ok"] is False
    assert "../outside.json" in result["unsafe_paths"]


def test_signed_snapshot_can_download_and_verify_fixed_https_snapshot(monkeypatch):
    base_url = "https://snapshot.example/cell"
    files = {
        path.relative_to(SIGNED_SNAPSHOT).as_posix(): path.read_bytes()
        for path in SIGNED_SNAPSHOT.rglob("*")
        if path.is_file() and ".git" not in path.parts
    }

    def fake_download(url: str) -> bytes:
        prefix = base_url + "/"
        assert url.startswith(prefix)
        relative_path = url[len(prefix):]
        if relative_path not in files:
            raise OSError("not found")
        return files[relative_path]

    monkeypatch.setattr("bitmap_memory_portal.signed_snapshot._download_url_bytes", fake_download)

    result = verify_signed_organa_snapshot(
        base_url,
        trusted_manifest_hash=TRUSTED_MANIFEST_HASH,
    )

    assert result["ok"] is True
    assert result["source"] == base_url


def test_downloaded_snapshot_rejects_unsafe_resource_path_before_fetch(monkeypatch):
    base_url = "https://snapshot.example/cell"
    manifest = json.loads((SIGNED_SNAPSHOT / "organa-cell.json").read_text(encoding="utf-8"))
    manifest["resources"][0]["path"] = "../../outside.json"
    fetched = []

    def fake_download(url: str) -> bytes:
        fetched.append(url)
        relative_path = url.removeprefix(base_url + "/")
        if relative_path == "organa-cell.json":
            return json.dumps(manifest).encode("utf-8")
        source = SIGNED_SNAPSHOT / relative_path
        return source.read_bytes()

    monkeypatch.setattr("bitmap_memory_portal.signed_snapshot._download_url_bytes", fake_download)

    result = verify_signed_organa_snapshot(base_url)

    assert result["ok"] is False
    assert "../../outside.json" in result["unsafe_paths"]
    assert all(".." not in url.removeprefix(base_url + "/") for url in fetched)


def test_frozen_snapshot_has_automation_entrypoint():
    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "verify_signed_snapshot.py"),
            str(SIGNED_SNAPSHOT),
            "--trusted-manifest-hash",
            TRUSTED_MANIFEST_HASH,
        ],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ok"] is True


def test_https_download_retries_with_curl_when_urlopen_fails(monkeypatch):
    expected = b"snapshot bytes"

    def fail_urlopen(*args, **kwargs):
        raise URLError("TLS EOF")

    def fake_run(command, **kwargs):
        assert command[:2] == ["curl", "-fsSL"]
        return subprocess.CompletedProcess(command, 0, stdout=expected, stderr=b"")

    monkeypatch.setattr("bitmap_memory_portal.signed_snapshot.urlopen", fail_urlopen)
    monkeypatch.setattr(subprocess, "run", fake_run)

    from bitmap_memory_portal.signed_snapshot import _download_url_bytes

    assert _download_url_bytes("https://snapshot.example/file.json") == expected
