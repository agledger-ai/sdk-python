"""The ``agledger-verify`` console script exposes the key-provenance controls
the package documents.

``verify_export`` has always honoured ``public_keys``, ``require_key_id`` and
``require_supplied_keys``, and the package metadata tells a reader to use
them, but the argument parser accepted none of them: every CLI run resolved
signatures against the keys the document carried, with no flag to refuse them.
A customer on the TypeScript CLI could run an independent-key audit and a
customer on this one could not.

Each test here drives ``run_cli`` the way the console script does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agledger.verify.cli import run_cli

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CORPUS = _REPO_ROOT / "testdata" / "conformance"
_EXPORT = _CORPUS / "export" / "valid-es256.json"
_DUMP = _CORPUS / "dump" / "valid"

_EXIT_OK = 0
_EXIT_VERIFICATION_FAILED = 1
_EXIT_USAGE = 2


def _embedded_keys() -> dict[str, str]:
    """The export's own signing keys, as a ``{keyId: spki_b64}`` map. Reusing
    them as out-of-band input is what isolates the provenance plumbing from key
    correctness: the verdict must not change, only the provenance tally."""
    doc = json.loads(_EXPORT.read_text())
    keys = (
        doc.get("exportMetadata", {}).get("signingPublicKeys")
        or doc["signingPublicKeys"]
    )
    if isinstance(keys, dict):
        return dict(keys)
    return {k["keyId"]: k["publicKey"] for k in keys}


def test_the_documented_flags_are_accepted(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        run_cli([str(_EXPORT), "--require-key-id", next(iter(_embedded_keys()))])
        == _EXIT_OK
    )
    assert "NOT ANCHORED" in capsys.readouterr().out


def test_without_a_trust_anchor_a_pass_says_it_is_not_trusted_and_how_to_pin(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_cli([str(_EXPORT)]) == _EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("[VERIFIED, NOT ANCHORED]")
    assert "supplied=0" in out
    assert "this is NOT a trusted verdict" in out
    assert "--trust-anchor sha256:<hex>" in out


def test_with_a_trust_anchor_a_pass_is_trusted_and_names_the_anchor(
    capsys: pytest.CaptureFixture[str],
) -> None:
    pin = json.loads(_EXPORT.read_text())["exportMetadata"]["anchoredFrom"]
    assert run_cli([str(_EXPORT), "--trust-anchor", pin]) == _EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("[PASS]")
    assert f"walked from {pin}" in out
    assert "(is one of your anchors)" in out


def test_a_trust_anchor_nothing_links_to_fails_every_signed_entry(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_cli([str(_EXPORT), "--trust-anchor", f"sha256:{'ab' * 32}"]) == _EXIT_VERIFICATION_FAILED
    assert "CHAIN_SIGNING_KEY_UNANCHORED" in capsys.readouterr().out


def test_a_malformed_trust_anchor_or_a_distrusted_key_without_one_is_a_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_cli([str(_EXPORT), "--trust-anchor", "15d63684b387235c"]) == _EXIT_USAGE
    assert "15d63684b387235c" in capsys.readouterr().err
    assert run_cli([str(_EXPORT), "--distrusted-key", f"sha256:{'ab' * 32}"]) == _EXIT_USAGE
    assert "--trust-anchor" in capsys.readouterr().err


@pytest.mark.parametrize("shape", ["map", "list", "envelope"])
def test_keys_accepts_every_documented_file_shape(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], shape: str
) -> None:
    """A map, a list of entries, and a saved ``GET /v1/verification-keys``
    envelope all resolve. The envelope matters because it is what a reader
    actually has on disk after fetching the keys."""
    keys = _embedded_keys()
    entries = [{"keyId": k, "publicKey": v} for k, v in keys.items()]
    payload = {"map": keys, "list": entries, "envelope": {"data": entries}}[shape]
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(payload))

    assert (
        run_cli([str(_EXPORT), "--keys", str(path), "--require-supplied-keys"])
        == _EXIT_OK
    )
    out = capsys.readouterr().out
    assert "supplied=3 embedded=0" in out
    # Where a key came from does not make it trusted: without a pin the pass
    # is still flagged.
    assert out.startswith("[VERIFIED, NOT ANCHORED]")


def test_require_supplied_keys_without_keys_refuses_the_embedded_ones(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The flag's whole purpose: an export that passes on its own embedded keys
    must fail when the run demands independent ones. A flag that parsed but did
    not reach the verifier would still return 0 here."""
    assert (
        run_cli([str(_EXPORT), "--require-supplied-keys"])
        == _EXIT_VERIFICATION_FAILED
    )
    assert "CHAIN_KEY_POLICY_VIOLATION" in capsys.readouterr().out


def test_require_key_id_rejects_an_unexpected_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_cli([str(_EXPORT), "--require-key-id", "not-the-signing-key"]) == (
        _EXIT_VERIFICATION_FAILED
    )
    assert "CHAIN_KEY_POLICY_VIOLATION" in capsys.readouterr().out


def test_the_key_policy_flags_are_refused_on_a_dump(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A dump carries its own signed key history, so an out-of-band key set has
    nothing to override. Accepting the flag silently would report an audit that
    honoured a policy it never applied."""
    assert run_cli([str(_DUMP), "--require-supplied-keys"]) == _EXIT_USAGE
    # @agledger/verify's refusal, word for word.
    assert capsys.readouterr().err == (
        "--keys / --require-key-id / --require-supplied-keys apply to /audit-export files only; a dump "
        "directory carries its own signed key history (vault_signing_keys.ndjson and "
        "vault_key_statements.ndjson). Pin it with --trust-anchor.\n"
    )


def test_a_malformed_keys_file_is_a_usage_error_not_a_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 1 and exit 2 mean opposite things, so a bad key file must never
    surface as evidence of tampering."""
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"some-key-id": 42}))
    assert run_cli([str(_EXPORT), "--keys", str(path)]) == _EXIT_USAGE
    assert "must be a" in capsys.readouterr().err


def test_a_missing_keys_file_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    absent = tmp_path / "absent.json"
    assert run_cli([str(_EXPORT), "--keys", str(absent)]) == _EXIT_USAGE
    # Node's words, as @agledger/verify prints them.
    assert capsys.readouterr().err == f"ENOENT: no such file or directory, open '{absent}'\n"


# --- the flag contract shared with @agledger/verify and `agledger verify` ---

_PIN = f"sha256:{'a' * 64}"


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["/nonexistent", "--trust-anchor", "abc"], '--trust-anchor "abc" is not sha256:<64 hex>. Each anchor is the full SHA-256'),
        (["/nonexistent", "--trust-anchor", f"{_PIN},{_PIN}"], f'--trust-anchor "{_PIN},{_PIN}" is not sha256:<64 hex>.'),
        (
            ["/nonexistent", "--trust-anchor", _PIN, "--distrusted-key", f"{_PIN}@2026-02-30T00:00:00Z"],
            f'--distrusted-key "{_PIN}@2026-02-30T00:00:00Z" is not sha256:<64 hex>, optionally followed by @<RFC 3339 instant>',
        ),
        (
            ["/nonexistent", "--trust-anchor", _PIN, "--distrusted-key", _PIN, "--distrusted-key", _PIN],
            f"--distrusted-key names {_PIN} twice.",
        ),
        (
            ["/nonexistent", "--distrusted-key", _PIN],
            "--distrusted-key acts only inside the key-statement walk, which runs from --trust-anchor; pass the pin as well.",
        ),
        (
            ["/nonexistent", "--trust-anchor", _PIN, "--distrusted-key", _PIN],
            f"{_PIN} is a --trust-anchor and a --distrusted-key with no instant, which leaves the pin nothing to vouch for.",
        ),
        # Beside a pin, a dated entry is taken: the pin vouches for what the key stored before the instant.
        (
            ["/nonexistent", "--trust-anchor", _PIN, "--distrusted-key", f"{_PIN}@2026-09-01T00:00:00Z"],
            "Cannot read /nonexistent: no such file or directory.",
        ),
        (["/nonexistent", "--trust-anchor", _PIN], "Cannot read /nonexistent: no such file or directory."),
        (
            ["/nonexistent", "--distrusted-keys", _PIN],
            "--distrusted-keys is now --distrusted-key, given once per key: --distrusted-key sha256:<hex>[@<RFC 3339 instant>].",
        ),
        (["/nonexistent", "--require-out-of-band-keys"], "--require-out-of-band-keys is now --require-supplied-keys"),
    ],
)
def test_a_refused_input_exits_2_with_the_shared_message(
    capsys: pytest.CaptureFixture[str], argv: list[str], message: str
) -> None:
    assert run_cli(argv) == _EXIT_USAGE
    assert capsys.readouterr().err.startswith(message)
    assert run_cli([*argv, "-f", "json"]) == _EXIT_USAGE
    out = capsys.readouterr().out
    if out:
        assert json.loads(out)["error"]["message"].startswith(message)


def test_a_prefix_of_a_flag_is_not_that_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli([str(_EXPORT), "--trust", _PIN]) == _EXIT_USAGE
    assert capsys.readouterr().err.startswith("Unknown flag: --trust\n\nagledger-verify: offline verifier")


@pytest.mark.parametrize("flag", ["-q", "--quiet"])
def test_quiet_is_refused_as_agledger_verify_refuses_it(flag: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli([str(_EXPORT), flag]) == _EXIT_USAGE
    assert capsys.readouterr().err.startswith(f"Unknown flag: {flag}\n\n")


@pytest.mark.parametrize(
    ("argv", "code", "first_line"),
    [
        ([str(_DUMP), "--trust-anchor", "sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e"], 0, "[PASS] AGLedger offline verification (dump)"),
        ([str(_DUMP)], 0, "[VERIFIED, NOT ANCHORED] AGLedger offline verification (dump)"),
        ([str(_DUMP), "--trust-anchor", f"sha256:{'ab' * 32}"], 1, "[FAIL] AGLedger offline verification (dump)"),
    ],
)
def test_the_headline_and_exit_code_per_verdict(
    capsys: pytest.CaptureFixture[str], argv: list[str], code: int, first_line: str
) -> None:
    assert run_cli(argv) == code
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == first_line
    explanation = {
        0: "  Nothing failed",
        1: "  Verification FAILED: the chain, the read log or the key statements do not hold up.",
    }[code]
    assert lines[1].startswith(explanation)


def test_a_key_note_is_listed_when_an_honest_rotation_off_a_key_distrusted_after_it_passes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fx = _REPO_ROOT / "tests" / "fixtures" / "distrusted-rotation"
    meta = json.loads((fx / "meta.json").read_text())
    argv = [str(fx / "export.json"), "--keys", str(fx / "keys.json"), "--trust-anchor", meta["pin"]]
    assert run_cli([*argv, "--distrusted-key", meta["distrust"]]) == _EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("[PASS]")
    assert "note: key " in out
    assert "which distrustedKeys distrusts" in out
