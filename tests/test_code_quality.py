"""Code-quality lint tests — the Python analogue of the monorepo's
``tests/code-quality.test.ts``. Scans source files for patterns that signal
low-quality or auto-generated code, and enforces the offline-verifier network
guarantee. Runs with ``pytest``.

The TypeScript suite's "no unnecessary async" and "clean dist before building"
rules have no Python analogue (async passthrough isn't a pattern here, and
hatchling builds emit no stale dist orphans), so they are intentionally absent.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "agledger"

# Network-capable modules an offline verifier must never import.
_NETWORK_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+(?:httpx|requests|urllib|http|socket|ssl|asyncio)\b"
)

# A comment line that is *only* a run of dashes/equals/box-drawing (>=10). A
# labelled divider like ``# --- Loader ---`` has text and far fewer dashes, so
# it does not match — that style is used deliberately in the verify package.
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
    nothing network-capable — the mechanical guarantee behind the offline claim.
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
