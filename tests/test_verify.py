import json

from bitmap_memory_portal.core import build_manifest, verify_manifest


def test_verify_manifest_passes_for_unchanged_source_folder(tmp_path):
    (tmp_path / "a.txt").write_text("A", encoding="utf-8")
    (tmp_path / "b.txt").write_text("B", encoding="utf-8")
    manifest = build_manifest(tmp_path, "981213.bitmap", "Demo", "v1")

    result = verify_manifest(manifest, tmp_path)

    assert result["ok"] is True
    assert result["checked_files"] == 2
    assert result["missing_files"] == []
    assert result["changed_files"] == []
    assert result["unexpected_files"] == []
    assert result["expected_merkle_root"] == manifest["merkle_root"]
    assert result["actual_merkle_root"] == manifest["merkle_root"]


def test_verify_manifest_detects_changed_missing_and_unexpected_files(tmp_path):
    (tmp_path / "a.txt").write_text("A", encoding="utf-8")
    (tmp_path / "b.txt").write_text("B", encoding="utf-8")
    manifest = build_manifest(tmp_path, "981213.bitmap", "Demo", "v1")

    (tmp_path / "a.txt").write_text("changed", encoding="utf-8")
    (tmp_path / "b.txt").unlink()
    (tmp_path / "extra.txt").write_text("extra", encoding="utf-8")

    result = verify_manifest(manifest, tmp_path)

    assert result["ok"] is False
    assert result["checked_files"] == 2
    assert result["changed_files"][0]["path"] == "a.txt"
    assert result["missing_files"] == ["b.txt"]
    assert result["unexpected_files"] == ["extra.txt"]
    assert result["actual_merkle_root"] != manifest["merkle_root"]
