"""Guard against a verifier script that exists in git but never reaches the container.

The Dockerfile originally copied scripts one file at a time. Adding a new signature scheme
therefore shipped a service whose API answered normally but whose verification failed with
`Cannot find module` - a deploy that reports success while the new feature is dead.

These tests fail as soon as the image and the code disagree about which scripts exist.
"""

import re
from pathlib import Path

from bitmap_memory_portal.claims import _SCHEME_SCRIPTS

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _copied_paths() -> set[str]:
    """Every source path the image actually receives."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    copied: set[str] = set()
    for line in text.splitlines():
        match = re.match(r"\s*COPY\s+(.*)", line, flags=re.IGNORECASE)
        if not match:
            continue
        parts = [p for p in match.group(1).split() if not p.startswith("--")]
        if len(parts) < 2:
            continue
        copied.update(parts[:-1])
    return copied


def _is_covered(script: str, copied: set[str]) -> bool:
    if script in copied:
        return True
    # A whole-directory copy covers everything beneath it.
    parent = str(Path(script).parent)
    return any(c.rstrip("/") == parent for c in copied)


def test_every_signature_scheme_script_reaches_the_container():
    copied = _copied_paths()
    missing = [
        f"scripts/{name}"
        for name in _SCHEME_SCRIPTS.values()
        if not _is_covered(f"scripts/{name}", copied)
    ]
    assert not missing, (
        "these verifier scripts are referenced by claims.py but never copied into the image, "
        f"so signature verification would fail in production: {missing}. "
        f"Dockerfile copies: {sorted(copied)}"
    )


def test_every_referenced_script_actually_exists_on_disk():
    """The reverse failure: a scheme registered in code with no script behind it."""
    for scheme, name in _SCHEME_SCRIPTS.items():
        path = REPO_ROOT / "scripts" / name
        assert path.is_file(), f"{scheme} maps to {name}, which does not exist"


def test_the_node_dependency_the_evm_script_needs_is_installed():
    """verify_evm_message.js uses @noble/curves and @noble/hashes via bip322-js."""
    package_json = (REPO_ROOT / "package.json").read_text(encoding="utf-8")
    assert "bip322-js" in package_json, (
        "bip322-js is what brings @noble/curves and @noble/hashes into the image; "
        "removing it silently breaks EVM signature recovery"
    )
    assert "npm ci" in DOCKERFILE.read_text(encoding="utf-8")
