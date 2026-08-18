"""Source hygiene checks over this package's own code: house style, plus the
offline-verifier network guarantee. The TypeScript packages run the equivalent
set from ``tests/code-quality.test.ts``. Runs with ``pytest``.

The TypeScript suite's "no unnecessary async" and "clean dist before building"
rules have no Python analogue (async passthrough isn't a pattern here, and
hatchling builds emit no stale dist orphans), so they are intentionally absent.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "agledger"

# Network-capable modules an offline verifier must never import.
_NETWORK_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+(?:httpx|requests|urllib|http|socket|ssl|asyncio)\b"
)

# A comment line that is *only* a run of dashes/equals/box-drawing (>=10). A
# labelled divider like ``# --- Loader ---`` has text and far fewer dashes, so
# it does not match: that style is used deliberately in the verify package.
_DIVIDER = re.compile(r"^\s*#\s*[-=═─━]{10,}\s*$")

_COPYRIGHT = re.compile(
    r"Patent Pending|Copyright 20\d{2} AGLedger LLC\. All rights reserved"
)

# Emoji / decorative pictograph ranges (mirrors the TS pattern).
_EMOJI = re.compile(
    "[\U0001f300-\U0001f9ff\U00002700-\U000027bf\U00002600-\U000026ff"
    "\U00002300-\U000023ff⭐⭕✅❌❎✨️]"
)


def _src_files() -> list[Path]:
    return [p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts]


def _rel(p: Path) -> str:
    return str(p.relative_to(SRC.parent.parent))


def test_no_emoji_in_source() -> None:
    violations: list[str] = []
    for f in _src_files():
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if _EMOJI.search(line):
                violations.append(f"{_rel(f)}:{i}  {line.strip()}")
    assert not violations, "Emoji found in source files:\n" + "\n".join(violations)


def test_no_decorative_dividers() -> None:
    violations: list[str] = []
    for f in _src_files():
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if _DIVIDER.match(line):
                violations.append(f"{_rel(f)}:{i}  {line.strip()}")
    assert not violations, "Decorative dividers found:\n" + "\n".join(violations)


def test_no_per_file_copyright() -> None:
    violations: list[str] = []
    for f in _src_files():
        head = "\n".join(f.read_text(encoding="utf-8").splitlines()[:10])
        if _COPYRIGHT.search(head):
            violations.append(_rel(f))
    assert not violations, "Per-file copyright found (use LICENSE):\n" + "\n".join(violations)


def test_offline_verifier_imports_no_network() -> None:
    """The verify package's value is producing a correct verdict even if the
    engine that produced the records is compromised. If it could reach the
    network it could be steered to phone home for a verdict, so it must import
    nothing network-capable: the mechanical guarantee behind the offline claim.
    """
    verify_dir = SRC / "verify"
    violations: list[str] = []
    for f in verify_dir.rglob("*.py"):
        if "__pycache__" in f.parts:
            continue
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if _NETWORK_IMPORT.match(line):
                violations.append(f"{_rel(f)}:{i}  {line.strip()}")
    assert not violations, "Network-capable import in offline verifier:\n" + "\n".join(violations)


# Truthiness tests on signing-key ids. None is the system-wide unsigned-mode
# marker for these fields; a truthiness test treats a tampered "" like None and
# skips the signature check (fail-open). The empty string must instead fall
# through to key resolution and fail as an unknown key. Six instances of this
# class shipped in the verifier wave before the sweep; this pins it at zero.
# Legal spellings: ``is None`` / ``is not None``.
_TRUTHY_SIGNING_KEY = re.compile(
    r"if\s+(?:not\s+)?(?:[\w.]+\.)?signing_key_id\s*(?::|\)|and\b|or\b)"
    r"|if\s+(?:not\s+)?(?:[\w.]+\.)?signingKeyId\s*(?::|\)|and\b|or\b)"
    r"|(?:[\w.]+\.)?signing_key_id\s+(?:and|or)\s"
)
_NULL_OK = re.compile(r"\bis\s+(?:not\s+)?None\b")


def test_no_truthiness_on_signing_key_ids() -> None:
    offenders: list[str] = []
    for path in _src_files():
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if _NULL_OK.search(line):
                continue
            if _TRUTHY_SIGNING_KEY.search(line):
                offenders.append(f"{_rel(path)}:{i}: {line.strip()}")
    assert offenders == [], "compare signing-key ids with `is None`, not truthiness"


# House style is plain punctuation, and it applies to shipped prose rather than
# just to docs: the wheel ships ``src/agledger/**`` verbatim, and a published
# artifact cannot be edited afterwards. Written as an escape so the pattern does
# not match its own source.
EM_DASH = "\u2014"

# ``testdata`` is generated upstream and digest-pinned by CORPUS-LOCK.json, so
# changes there have to be made at the generator. CHANGELOG.md is history.
_SKIP_DIRS = {".git", ".venv", "__pycache__", "dist", "build", "testdata", ".claude"}


def _prose_files() -> list[Path]:
    files: list[Path] = []
    for pattern in ("*.py", "*.md", "*.toml", "*.yml", "*.yaml"):
        for path in ROOT.rglob(pattern):
            if _SKIP_DIRS & set(path.parts):
                continue
            if path.name == "CHANGELOG.md":
                continue
            files.append(path)
    return files


def test_no_em_dashes() -> None:
    """Source, tests and shipped Markdown carry no em dashes."""
    violations: list[str] = []
    for path in _prose_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if EM_DASH in line:
                violations.append(f"{_rel(path)}:{lineno}  {line.strip()}")
    assert not violations, "Em dashes found:\n" + "\n".join(violations)
