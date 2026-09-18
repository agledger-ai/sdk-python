"""``agent_keys`` on the dump path and in ``agledger-verify``, and which
input-gated checks ran.

The Python mirror of ``@agledger/verify``'s ``agent-keys.test.ts``, on the same
unmodified 27-entry dump slice from a live 1.8.0 instance (three chains: a
cert-signed lifecycle whose key was kept, a second cert whose key was not, and
an API-key lifecycle) and the same cert-signed export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agledger.verify import load_dump, verify_dump, verify_export
from agledger.verify.cli import run_cli

LIVE = Path(__file__).parent / "fixtures" / "live-1.8.0"
DUMP = str(LIVE / "dump")
EXPORT = str(LIVE / "export-cert-lifecycle.json")
KEY_FILE = str(LIVE / "agent-cert-key.json")
KEY_ENTRY: dict[str, Any] = json.loads((LIVE / "agent-cert-key.json").read_text())
JWK: dict[str, str] = KEY_ENTRY["publicKeyJwk"]
ALL_APPLIED = dict.fromkeys(("payload_binding", "oidc_actor", "key_temporal", "agent_signature"), "applied")


def _other_jwk() -> dict[str, str]:
    import base64

    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = run_cli(args)
    out = capsys.readouterr()
    return code, out.out, out.err


# --- library ---


def test_the_dump_re_verifies_the_supplied_cert_and_leaves_the_others_unchecked():
    report = verify_dump(load_dump(DUMP), agent_keys=[JWK])
    assert report.ok
    assert report.vault.entry_count == 27
    assert report.vault.optional_checks == ALL_APPLIED
    assert (report.vault.agent_signatures_present, report.vault.agent_signatures_verified) == (12, 6)


def test_without_keys_the_dump_reports_the_check_not_run_and_no_verdict_changes():
    report = verify_dump(load_dump(DUMP))
    assert report.ok
    assert report.vault.optional_checks["agent_signature"] == "skipped_no_input"
    assert (report.vault.agent_signatures_present, report.vault.agent_signatures_verified) == (12, 0)


def test_a_bad_key_is_refused_at_the_boundary_on_the_dump_path():
    with pytest.raises(TypeError):
        verify_dump(load_dump(DUMP), agent_keys=[{"kty": "RSA"}])


def test_the_export_reports_every_input_gated_check_it_ran():
    # Same answer as verify-core 1.5.0 on this export: the export carries the
    # binding payload, the actor OIDC columns and the key windows.
    result = verify_export(json.loads(Path(EXPORT).read_text()), agent_keys=[JWK])
    assert result.valid
    assert result.optional_checks == ALL_APPLIED
    assert (result.agent_signatures.present, result.agent_signatures.verified) == (6, 6)


def test_a_rewritten_actor_oidc_subject_on_an_export_fails_the_actor_check():
    # The export path now runs the OIDC-actor cross-check when the export
    # carries actorOidcSynthesized, as verify-core does.
    doc = json.loads(Path(EXPORT).read_text())
    entry = next(e for e in doc["entries"] if e.get("actorOidcSynthesized") is True)
    entry["actorOidcSub"] = "forged"
    result = verify_export(doc)
    assert not result.valid
    assert result.broken_at is not None and result.broken_at.code == "CHAIN_OIDC_ACTOR_MISMATCH"


def test_an_export_written_after_its_key_retired_fails_the_temporal_check():
    doc = json.loads(Path(EXPORT).read_text())
    (key_id, window), = doc["exportMetadata"]["signingKeyWindows"].items()
    doc["exportMetadata"]["signingKeyWindows"][key_id] = {**window, "retiredAt": "2026-01-01T00:00:00.000Z"}
    result = verify_export(doc)
    assert not result.valid
    assert result.broken_at is not None and result.broken_at.code == "CHAIN_KEY_EXPIRED"


# --- CLI ---


def test_cli_dump_with_agent_keys(capsys: pytest.CaptureFixture[str]):
    code, out, _ = _run([DUMP, "--agent-keys", KEY_FILE, "-f", "json"], capsys)
    assert code == 0
    vault = json.loads(out)["vault"]
    assert vault["optionalChecks"] == ALL_APPLIED
    assert vault["agentSignatures"] == {"present": 12, "verified": 6}


def test_cli_dump_text_says_which_signatures_were_checked(capsys: pytest.CaptureFixture[str]):
    _, out, _ = _run([DUMP, "--agent-keys", KEY_FILE], capsys)
    assert "agent sigs  : present=12 verified=6 (checked; 6 not verified: no key supplied" in out
    _, out, _ = _run([DUMP], capsys)
    assert "agent sigs  : present=12 verified=0 (NOT checked" in out


def test_cli_export_with_agent_keys(capsys: pytest.CaptureFixture[str]):
    code, out, _ = _run([EXPORT, "--agent-keys", KEY_FILE, "-f", "json"], capsys)
    assert code == 0
    report = json.loads(out)
    assert report["optionalChecks"]["agent_signature"] == "applied"
    assert report["agentSignatures"] == {"present": 6, "verified": 6}
    _, out, _ = _run([EXPORT, "--agent-keys", KEY_FILE], capsys)
    assert "agent signatures  : present=6 verified=6 (checked)" in out
    _, out, _ = _run([EXPORT], capsys)
    assert "present=6 verified=0 (NOT checked: pass --agent-keys" in out


@pytest.mark.parametrize(
    "shape",
    [
        lambda: JWK,
        lambda: [_other_jwk(), JWK],
        lambda: {"keys": [JWK, _other_jwk()]},
        lambda: KEY_ENTRY,
        lambda: [{"publicKeyJwk": _other_jwk()}, KEY_ENTRY],
        lambda: {"keys": [KEY_ENTRY]},
    ],
    ids=["jwk", "list", "jwk-set", "publicKeyJwk-entry", "list-of-entries", "set-of-entries"],
)
def test_cli_accepts_every_key_file_shape(shape: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(shape()))
    code, out, _ = _run([EXPORT, "--agent-keys", str(keys), "-f", "json"], capsys)
    assert code == 0
    assert json.loads(out)["agentSignatures"] == {"present": 6, "verified": 6}


@pytest.mark.parametrize("target", [DUMP, EXPORT], ids=["dump", "export"])
@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "Cannot read --agent-keys file"),
        ("{not json", "Cannot read --agent-keys file"),
        ("[]", "holds no keys"),
        ('{"keys": []}', "holds no keys"),
        ('[{"kty": "RSA", "n": "x", "e": "AQAB"}]', "entry 0 is not an Ed25519 public-key JWK"),
    ],
    ids=["missing", "invalid-json", "empty-list", "empty-set", "not-ed25519"],
)
def test_a_malformed_key_file_is_a_usage_error_in_both_modes(
    target: str, content: str | None, message: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    keys = tmp_path / "keys.json"
    if content is not None:
        keys.write_text(content)
    code, out, err = _run([target, "--agent-keys", str(keys)], capsys)
    assert code == 2
    assert out == ""
    assert message in err
