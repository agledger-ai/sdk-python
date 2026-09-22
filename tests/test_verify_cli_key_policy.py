"""The ``agledger-verify`` console script exposes the key-provenance controls
the package documents.

``verify_export`` has always honoured ``public_keys``, ``require_key_id`` and
``require_out_of_band_keys``, and the package metadata tells a reader to use
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
    assert "PASS" in capsys.readouterr().out


def test_without_keys_a_pass_says_it_is_not_independent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_cli([str(_EXPORT)]) == _EXIT_OK
    out = capsys.readouterr().out
    assert "out-of-band=0" in out
    assert "WARNING" in out
    assert "not independence" in out


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
        run_cli([str(_EXPORT), "--keys", str(path), "--require-out-of-band-keys"])
        == _EXIT_OK
    )
    out = capsys.readouterr().out
    assert "out-of-band=3 embedded=0" in out
    # The independence warning is the no-out-of-band-keys case only.
    assert "WARNING" not in out


def test_require_out_of_band_keys_without_keys_refuses_the_embedded_ones(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The flag's whole purpose: an export that passes on its own embedded keys
    must fail when the run demands independent ones. A flag that parsed but did
    not reach the verifier would still return 0 here."""
    assert (
        run_cli([str(_EXPORT), "--require-out-of-band-keys"])
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
    assert run_cli([str(_DUMP), "--require-out-of-band-keys"]) == _EXIT_USAGE
    assert "audit-export files only" in capsys.readouterr().err


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
    assert (
        run_cli([str(_EXPORT), "--keys", str(tmp_path / "absent.json")]) == _EXIT_USAGE
    )
    assert "Cannot read --keys file" in capsys.readouterr().err
