import hashlib
import json
from pathlib import Path

from bitmap_memory_portal.core import (
    file_sha256,
    merkle_root,
    build_manifest,
)


def test_file_sha256_hashes_file_bytes(tmp_path):
    p = tmp_path / "hello.txt"
    p.write_text("hello", encoding="utf-8")

    assert file_sha256(p) == hashlib.sha256(b"hello").hexdigest()


def test_merkle_root_duplicates_last_hash_for_odd_leaf_count():
    leaves = ["a" * 64, "b" * 64, "c" * 64]
    ab = hashlib.sha256(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1])).hexdigest()
    cc = hashlib.sha256(bytes.fromhex(leaves[2]) + bytes.fromhex(leaves[2])).hexdigest()
    expected = hashlib.sha256(bytes.fromhex(ab) + bytes.fromhex(cc)).hexdigest()

    assert merkle_root(leaves) == expected


def test_build_manifest_includes_relative_paths_hashes_root_and_previous(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.txt").write_text("A", encoding="utf-8")
    (tmp_path / "b.txt").write_text("B", encoding="utf-8")

    manifest = build_manifest(
        source_dir=tmp_path,
        bitmap="981213.bitmap",
        title="Patoshi Bitmap Memory Portal",
        version="2026-05-demo",
        previous_manifest_hash="sha256:prev",
        description="demo archive",
    )

    assert manifest["portal_type"] == "bitmap-memory-portal"
    assert manifest["bitmap"] == "981213.bitmap"
    assert manifest["title"] == "Patoshi Bitmap Memory Portal"
    assert manifest["version"] == "2026-05-demo"
    assert manifest["previous_manifest_hash"] == "sha256:prev"
    assert manifest["files_count"] == 2
    assert manifest["total_size_bytes"] == 2
    assert [f["path"] for f in manifest["files"]] == ["b.txt", "docs/a.txt"]
    assert manifest["merkle_root"]
    assert manifest["manifest_hash"].startswith("sha256:")

    encoded = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
    assert "demo archive" in encoded
