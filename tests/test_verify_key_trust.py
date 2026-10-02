"""``trust_anchors`` on the export and dump paths, over the corpus's real
exports and dumps, and the walk on a host that cannot compute a key's
algorithm. Ports of verify-core's ``export-key-trust.test.ts``,
``dump-key-trust.test.ts``, ``key-statements-fips.test.ts`` and
``key-statements-zero-signature.test.ts``."""

from __future__ import annotations

import copy
import importlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import cbor2
import pytest

from agledger.verify import (
    compute_key_trust,
    key_statement_from_dump_row,
    load_dump,
    spki_sha256,
    trust_key_from_dump_row,
    verify_dump,
    verify_export,
)
from agledger.verify.key_statements import instant_ms
from agledger.verify.verify_dump import report_codes
from agledger.verify.verify_export import KeyCache, RegisteredKey, apply_key_trust

from .key_statement_helpers import (
    T0,
    T1,
    T2,
    T3,
    make_key,
    make_opaque_key,
    row,
    statement,
    under_admitted_key,
)

_CONFORMANCE = Path(__file__).resolve().parents[1] / "testdata" / "conformance"
_EXPORT = _CONFORMANCE / "export"
STRANGER = f"sha256:{'ab' * 32}"


def _load(name: str) -> dict[str, Any]:
    return json.loads((_EXPORT / name).read_text())


def _pin_of(exp: dict[str, Any]) -> str:
    pin = exp["exportMetadata"].get("anchoredFrom")
    assert pin, "the corpus export carries anchoredFrom"
    return str(pin)


# --- verify_export with trust_anchors ---


def test_without_anchors_the_result_says_no_key_was_anchored_and_the_check_did_not_run() -> None:
    r = verify_export(_load("valid.json"))
    assert r.valid is True
    assert r.optional_checks["key_anchoring"] == "skipped_no_input"
    assert r.key_trust.status == "no_anchor"
    assert "No trustAnchors" in r.key_trust.detail
    assert r.key_trust.anchored_from == _pin_of(_load("valid.json"))
    assert r.key_trust.anchored_from_pinned is None


def test_pinned_on_the_vault_key_every_entry_is_anchored() -> None:
    exp = _load("valid.json")
    r = verify_export(exp, trust_anchors=[_pin_of(exp)])
    assert r.valid is True
    assert r.optional_checks["key_anchoring"] == "applied"
    kt = r.key_trust
    assert (kt.status, kt.order, kt.anchored_from_pinned, kt.unanchored_key_ids, kt.findings) == (
        "walked",
        "written",
        True,
        [],
        [],
    )
    assert kt.anchored_key_ids == [exp["entries"][0]["integrity"]["signingKeyId"]]


def test_pinned_on_a_key_nothing_links_to_every_signed_entry_fails_unanchored() -> None:
    r = verify_export(_load("valid.json"), trust_anchors=[STRANGER])
    assert r.valid is False
    assert r.broken_at is not None
    assert (r.broken_at.position, r.broken_at.code) == (1, "CHAIN_SIGNING_KEY_UNANCHORED")
    assert all(e.code == "CHAIN_SIGNING_KEY_UNANCHORED" for e in r.entries)
    assert r.key_trust.anchored_from_pinned is False


def test_an_embedded_key_with_no_statement_is_unanchored_the_key_substitution_fixture_fails() -> None:
    exp = _load("key-substitution.json")
    assert verify_export(exp).valid is True
    r = verify_export(exp, trust_anchors=[_pin_of(exp)])
    assert r.broken_at is not None
    assert (r.broken_at.position, r.broken_at.code) == (2, "CHAIN_SIGNING_KEY_UNANCHORED")
    assert r.key_trust.unanchored_key_ids == [exp["entries"][1]["integrity"]["signingKeyId"]]


def test_walks_a_three_key_history_across_an_algorithm_change_from_the_servers_current_key() -> None:
    exp = _load("valid-es256.json")
    keys = json.loads((_EXPORT / "keys-oob-es256.json").read_text())
    r = verify_export(exp, public_keys=keys, trust_anchors=[_pin_of(exp)])
    assert r.valid is True
    assert len(r.key_trust.anchored_key_ids) == 3
    assert r.key_trust.findings == []


def test_a_statement_that_does_not_verify_is_key_statement_invalid_and_fails_the_verdict() -> None:
    import base64

    exp = _load("valid.json")
    key_id = exp["entries"][0]["integrity"]["signingKeyId"]
    genesis = exp["exportMetadata"]["signingKeyStatements"][key_id][0]
    data = bytearray(base64.b64decode(genesis["cose"][0]))
    data[-1] ^= 0xFF
    genesis["cose"][0] = base64.b64encode(bytes(data)).decode()
    r = verify_export(exp, trust_anchors=[_pin_of(exp)])
    assert r.valid is False
    assert r.broken_at is not None
    assert (r.broken_at.position, r.broken_at.code) == (0, "KEY_STATEMENT_INVALID")
    # The pin is the key itself, so the entries stay anchored.
    assert all(e.valid for e in r.entries)


def test_entries_are_graded_against_the_signed_window_and_a_column_that_says_otherwise_is_a_finding() -> None:
    exp = _load("valid.json")
    key_id = exp["entries"][0]["integrity"]["signingKeyId"]
    windows = exp["exportMetadata"]["signingKeyWindows"]
    # The column claims the key was retired before the first entry.
    windows[key_id] = {"activatedAt": windows[key_id]["activatedAt"], "retiredAt": "2000-01-01T00:00:00.000Z"}
    unpinned = verify_export(exp)
    assert unpinned.broken_at is not None and unpinned.broken_at.code == "CHAIN_KEY_EXPIRED"
    r = verify_export(exp, trust_anchors=[_pin_of(exp)])
    assert all(e.valid for e in r.entries)
    assert [f.code for f in r.key_trust.findings] == ["KEY_CLOSURE_INVALID"]
    assert r.valid is False

    drifted = _load("valid.json")
    drifted["exportMetadata"]["signingKeyWindows"][key_id] = {"activatedAt": "2026-01-01T00:00:00.000Z", "retiredAt": None}
    got = verify_export(drifted, trust_anchors=[_pin_of(drifted)])
    assert [f.code for f in got.key_trust.findings] == ["CHAIN_KEY_WINDOW_DRIFT"]


def test_walks_the_statements_a_supplied_verification_keys_entry_carries() -> None:
    exp = _load("valid.json")
    key_id = exp["entries"][0]["integrity"]["signingKeyId"]
    statements = exp["exportMetadata"]["signingKeyStatements"][key_id]
    del exp["exportMetadata"]["signingKeyStatements"]
    public_keys = [{"keyId": key_id, "publicKey": exp["exportMetadata"]["signingPublicKeys"][key_id], "statements": statements}]
    r = verify_export(exp, public_keys=public_keys, trust_anchors=[_pin_of(_load("valid.json"))], require_supplied_keys=True)
    assert r.valid is True
    assert (r.key_provenance.supplied, r.key_provenance.embedded) == (3, 0)


def test_walks_the_statements_of_the_sdks_own_verification_key_models() -> None:
    from agledger.types import VerificationKey

    exp = _load("valid.json")
    key_id = exp["entries"][0]["integrity"]["signingKeyId"]
    window = exp["exportMetadata"]["signingKeyWindows"][key_id]
    model = VerificationKey.model_validate(
        {
            "keyId": key_id,
            "algorithm": "Ed25519",
            "publicKey": exp["exportMetadata"]["signingPublicKeys"][key_id],
            "status": "active",
            "activatedAt": window["activatedAt"],
            "retiredAt": None,
            "statements": exp["exportMetadata"]["signingKeyStatements"][key_id],
        }
    )
    del exp["exportMetadata"]["signingKeyStatements"]
    r = verify_export(exp, public_keys=[model], trust_anchors=[_pin_of(_load("valid.json"))])
    assert r.valid is True
    assert r.key_trust.anchored_key_ids == [key_id]


def test_a_statement_the_export_and_a_supplied_key_document_both_carry_is_walked_once() -> None:
    from agledger.types import VerificationKey

    exp = _load("valid.json")
    key_id = exp["entries"][0]["integrity"]["signingKeyId"]
    model = VerificationKey.model_validate(
        {
            "keyId": key_id,
            "algorithm": "Ed25519",
            "publicKey": exp["exportMetadata"]["signingPublicKeys"][key_id],
            "status": "active",
            "statements": exp["exportMetadata"]["signingKeyStatements"][key_id],
        }
    )
    r = verify_export(exp, public_keys=[model], trust_anchors=[_pin_of(exp)])
    # A second copy of the genesis would read as an admission after the first.
    assert r.valid is True
    assert r.key_trust.findings == []


def test_refuses_a_key_both_pinned_and_distrusted_as_the_server_refuses_to_start_with_it() -> None:
    exp = _load("valid.json")
    for distrust in (_pin_of(exp), f"{_pin_of(exp)}@2026-09-01T00:00:00Z"):
        with pytest.raises(TypeError, match="both a trust anchor and a distrusted key"):
            verify_export(exp, trust_anchors=[_pin_of(exp)], distrusted_keys=[distrust])


def test_a_distrusted_key_with_no_instant_and_no_retirement_is_trusted_for_nothing_though_its_root_is_pinned() -> None:
    exp, pin, key = under_admitted_key()
    assert verify_export(copy.deepcopy(exp), trust_anchors=[pin]).valid is True
    r = verify_export(exp, trust_anchors=[pin], distrusted_keys=[f"sha256:{key.digest}"])
    assert r.broken_at is not None and r.broken_at.code == "CHAIN_SIGNING_KEY_UNANCHORED"


def test_a_key_distrusted_from_an_instant_and_never_retired_fails_what_it_wrote_after_worded_as_the_cutoff() -> None:
    exp, pin, key = under_admitted_key()
    # A millisecond after the first entry's write time, before the second's.
    first_ms = cast("int", instant_ms(exp["entries"][0]["createdAt"]))
    assert first_ms + 1 < cast("int", instant_ms(exp["entries"][1]["createdAt"]))
    at = datetime.fromtimestamp((first_ms + 1) / 1000, tz=UTC)
    cutoff = f"{at.strftime('%Y-%m-%dT%H:%M:%S')}.{(first_ms + 1) % 1000:03d}000Z"
    r = verify_export(exp, trust_anchors=[pin], distrusted_keys=[f"sha256:{key.digest}@{cutoff}"])
    key_id = key.kid
    assert r.entries[0].valid
    assert r.broken_at is not None
    assert (r.broken_at.position, r.broken_at.code) == (2, "CHAIN_KEY_EXPIRED")
    assert r.broken_at.detail == (
        f"Entry written {exp['entries'][1]['createdAt']} postdates {cutoff}, the instant distrustedKeys "
        f"(VAULT_DISTRUSTED_KEYS on the Server) gives for key {key_id}; the key was not retired then."
    )
    assert "retirement" not in (r.broken_at.detail or "")
    # Not a retirement, so the active registry column is no drift.
    assert r.key_trust.findings == []


def test_refuses_a_malformed_anchor_or_distrusted_key_by_name() -> None:
    with pytest.raises(TypeError, match="15d63684b387235c"):
        verify_export(_load("valid.json"), trust_anchors=["15d63684b387235c"])
    with pytest.raises(TypeError):
        verify_export(_load("valid.json"), trust_anchors=[STRANGER], distrusted_keys=["sha256:xyz"])


def test_an_empty_trust_anchors_is_the_same_as_none() -> None:
    exp = _load("key-substitution.json")
    r = verify_export(exp, trust_anchors=[])
    assert r == verify_export(exp)
    assert r.key_trust.status == "no_anchor"


def _unsigned_with_anchored_key() -> tuple[dict[str, Any], str, str]:
    """unsigned.json carrying valid.json's key and statements, so a pinned walk
    anchors a key its entries never use."""
    exp = _load("unsigned.json")
    signed = _load("valid.json")
    exp["exportMetadata"]["signingPublicKeys"] = signed["exportMetadata"]["signingPublicKeys"]
    exp["exportMetadata"]["signingKeyStatements"] = signed["exportMetadata"]["signingKeyStatements"]
    key_id = next(iter(signed["exportMetadata"]["signingKeyWindows"]))
    return exp, _pin_of(signed), signed["exportMetadata"]["signingKeyWindows"][key_id]["activatedAt"]


def _ms(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def test_pinned_unsigned_entries_before_the_anchored_keys_signed_activation_stay_reduced_coverage() -> None:
    exp, pin, activated_at = _unsigned_with_anchored_key()
    assert all(_ms(e["createdAt"]) < _ms(activated_at) for e in exp["entries"])
    r = verify_export(exp, trust_anchors=[pin])
    assert r.valid is True
    assert len(r.key_trust.anchored_key_ids) == 1
    assert r.signature_coverage.skipped == 3


def test_pinned_unsigned_entries_after_the_anchored_keys_signed_activation_fail_with_the_windows_stripped() -> None:
    exp, pin, activated_at = _unsigned_with_anchored_key()
    # An hour after the anchored key's signed activation.
    after = datetime.fromtimestamp((cast("int", instant_ms(activated_at)) + 3_600_000) / 1000, tz=UTC)
    for e in exp["entries"]:
        e["createdAt"] = after.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    signed = _load("valid.json")
    with_windows = copy.deepcopy(exp)
    with_windows["exportMetadata"]["signingKeyWindows"] = signed["exportMetadata"]["signingKeyWindows"]
    got = verify_export(with_windows, trust_anchors=[pin])
    assert got.broken_at is not None and got.broken_at.code == "CHAIN_ENTRY_UNSIGNED"
    # The windows are the export's unsigned word; without them the statements still date the key.
    exp["exportMetadata"].pop("signingKeyWindows", None)
    r = verify_export(exp, trust_anchors=[pin])
    assert r.valid is False
    assert r.broken_at is not None
    assert (r.broken_at.position, r.broken_at.code) == (1, "CHAIN_ENTRY_UNSIGNED")
    # A window moved later cannot loosen it either.
    late = copy.deepcopy(with_windows)
    for w in late["exportMetadata"]["signingKeyWindows"].values():
        w["activatedAt"] = "2027-01-01T00:00:00.000Z"
    moved = verify_export(late, trust_anchors=[pin])
    assert moved.broken_at is not None and moved.broken_at.code == "CHAIN_ENTRY_UNSIGNED"
    # Without a pin nothing is signed, and nothing dates the key.
    assert verify_export(exp).valid is True


def test_an_unsigned_history_needs_no_anchor_to_stay_reduced_coverage() -> None:
    r = verify_export(_load("unsigned.json"), trust_anchors=[STRANGER])
    assert r.valid is True
    assert r.signature_coverage.skipped == 3


# --- the walk over the dump corpus ---


def _ndjson(vector: str, name: str) -> list[dict[str, Any]]:
    text = (_CONFORMANCE / vector / name).read_text()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _grade(vector: str, anchors: list[str]) -> list[str]:
    """Every code the walk and the logs it grades report for one dump."""
    report = verify_dump(load_dump(str(_CONFORMANCE / vector)), trust_anchors=anchors)
    assert report.key_trust.order == "written"
    return list(report_codes(report))


def _current_pin(vector: str) -> str:
    """The pin an operator hands an auditor: the Server's current key, the most
    recently activated key some statement admits (a planted row has none)."""
    admitted = {s["subject_key_id"] for s in _ndjson(vector, "vault_key_statements.ndjson") if s["kind"] != "closure"}
    keys = [k for k in _ndjson(vector, "vault_signing_keys.ndjson") if k["key_id"] in admitted]
    key = max(keys, key=lambda k: _ms(k.get("activated_at") or "1970-01-01T00:00:00Z"))
    return f"sha256:{spki_sha256(key['public_key'])}"


_MANIFEST = json.loads((_CONFORMANCE / "manifest-dump.json").read_text())
_PINNED = [v for v in _MANIFEST["vectors"] if (v.get("options") or {}).get("trustAnchors") is not None]


def test_the_dump_corpus_carries_vectors_that_pin_trust_anchors() -> None:
    assert len(_PINNED) >= 4


@pytest.mark.parametrize(
    "vector", _PINNED, ids=[f"{v['file']}:{v.get('failureCode') or v['expect']}" for v in _PINNED]
)
def test_a_vector_that_pins_trust_anchors_holds_its_verdict(vector: dict[str, Any]) -> None:
    codes = _grade(vector["file"], vector["options"]["trustAnchors"])
    if vector["expect"] == "pass":
        assert codes == []
    else:
        assert vector["failureCode"] in codes


@pytest.mark.parametrize(
    "vector", ["dump/valid", "dump/valid-es256", "dump/valid-identity", "dump/valid-unsigned-history-then-signed"]
)
def test_a_pass_vector_pinned_on_the_servers_current_key_verifies_clean(vector: str) -> None:
    # The column-edit vector valid-rotation-boundary is left out: its
    # activated_at column was moved off the signed value, which the walk
    # reports as CHAIN_KEY_WINDOW_DRIFT (see below).
    report = verify_dump(load_dump(str(_CONFORMANCE / vector)), trust_anchors=[_current_pin(vector)])
    assert report.vault.record_count > 0
    assert list(report_codes(report)) == []
    assert report.verdict == "trusted"
    assert report.key_trust.unanchored_key_ids == []


def test_valid_es256_walks_three_keys_and_the_forced_closure_cuts_the_first_key_off() -> None:
    vector = "dump/valid-es256"
    trust = compute_key_trust(
        keys=[trust_key_from_dump_row(k) for k in _ndjson(vector, "vault_signing_keys.ndjson")],
        statements=[key_statement_from_dump_row(s) for s in _ndjson(vector, "vault_key_statements.ndjson")],
        trust_anchors=[_current_pin(vector)],
    )
    assert len(trust.trusted) == 3
    counts = trust.statements
    assert (counts.total, counts.valid, counts.invalid, counts.unverifiable) == (4, 4, 0, 0)
    genesis = next(s for s in _ndjson(vector, "vault_key_statements.ndjson") if s["kind"] == "genesis")
    first = next(k for k in _ndjson(vector, "vault_signing_keys.ndjson") if k["key_id"] == genesis["subject_key_id"])
    assert "CHAIN_SIGNING_KEY_UNANCHORED" in _grade(vector, [f"sha256:{spki_sha256(first['public_key'])}"])


def test_chain_signing_key_unanchored_pinned_on_the_vault_key_fails_the_planted_entry() -> None:
    vector = "dump/chain-signing-key-unanchored"
    assert "CHAIN_SIGNING_KEY_UNANCHORED" in _grade(vector, [_current_pin(vector)])


def test_the_key_window_vectors_sign_the_window_they_test_and_grade_as_their_manifest_codes_pinned() -> None:
    # Each signs the window it tests and sets the column to the signed value,
    # so pinned on the vault key there is no drift and no closure finding:
    # only the code the manifest names, or nothing.
    for v in _PINNED:
        if v["file"] in ("dump/valid-rotation-boundary", "dump/chain-key-not-yet-active", "dump/chain-key-expired"):
            want = [v["failureCode"]] if v["expect"] == "fail" else []
            assert sorted(set(_grade(v["file"], v["options"]["trustAnchors"]))) == want, v["file"]


def test_a_dump_without_anchors_passes_flagged_and_says_so() -> None:
    report = verify_dump(load_dump(str(_CONFORMANCE / "dump/valid")))
    assert report.ok is True
    assert report.verdict == "unanchored"
    assert report.key_trust.status == "no_anchor"
    assert report.to_json()["verdict"] == "unanchored"
    assert report.to_json()["keyTrust"]["status"] == "no_anchor"


def test_a_dump_distrusted_key_needs_trust_anchors() -> None:
    with pytest.raises(TypeError, match="trust_anchors"):
        verify_dump(load_dump(str(_CONFORMANCE / "dump/valid")), distrusted_keys=[STRANGER])


def test_a_read_log_and_checkpoints_under_an_unanchored_key_fail_their_own_codes() -> None:
    # Pin a key nothing links to: every signed row names an unanchored key.
    codes = _grade("dump/valid", [STRANGER])
    for code in ("CHAIN_SIGNING_KEY_UNANCHORED", "CHECKPOINT_KEY_UNANCHORED", "TENANT_READ_KEY_UNANCHORED"):
        assert code in codes
    # The read log stops at its first finding, one per org as the engine
    # reports it, so the tree head behind that leaf is not graded.
    assert "TENANT_CHECKPOINT_KEY_UNANCHORED" not in codes


def test_a_trusted_keys_spki_filed_under_another_key_id_is_unanchored() -> None:
    c = make_key()
    trust = compute_key_trust(
        keys=[], statements=[statement("genesis", c, signers=[c])], trust_anchors=[f"sha256:{c.digest}"]
    )
    key = RegisteredKey(spki_base64=c.public_key, source="embedded")
    other = "eeeeeeeeeeeeeeee" if c.kid == "ffffffffffffffff" else "ffffffffffffffff"
    assert apply_key_trust(KeyCache({c.kid: key}), trust).entry(c.kid).trust == "anchored"  # type: ignore[union-attr]
    assert apply_key_trust(KeyCache({other: key}), trust).entry(other).trust == "unanchored"  # type: ignore[union-attr]



# --- a host that cannot compute a key's algorithm ---


@pytest.fixture
def fips_host(monkeypatch: pytest.MonkeyPatch) -> Any:
    """EdDSA verify raises, everything else is real, the way
    ``test_verify_fips_runtime`` stands in a FIPS provider."""
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    runtime = importlib.import_module("agledger._runtime_crypto")
    runtime._CACHE.clear()

    def refuse(self: Any, signature: bytes, data: bytes) -> None:
        raise UnsupportedAlgorithm("ed25519 is not supported by this backend")

    monkeypatch.setattr(type(Ed25519PrivateKey.generate().public_key()), "verify", refuse)
    yield
    runtime._CACHE.clear()


def _fips_history() -> tuple[Any, Any, Any, list[Any]]:
    k0, k1, a = make_opaque_key(), make_opaque_key(), make_key("ES256")
    g0 = statement("genesis", k0, signers=[k0], created_at=T0)
    s01 = statement("succession", k1, endorser=k0, signers=[k0, k1], activated_at=T0, created_at=T0)
    c0 = statement("closure", k0, endorser=k1, signers=[k1], retired_at=T1, created_at=T1)
    s1a = statement("succession", a, endorser=k1, signers=[k1, a], activated_at=T1, created_at=T1)
    c1 = statement("closure", k1, endorser=a, signers=[a], retired_at=T2, created_at=T2)
    return k0, k1, a, [g0, s01, c0, s1a, c1]


@pytest.mark.usefixtures("fips_host")
def test_the_opaque_history_is_undecided_never_trusted_and_a_forged_statement_under_an_opaque_key_decides_nothing() -> None:
    k0, k1, a, history = _fips_history()
    x, y = make_opaque_key(), make_opaque_key()
    into_k1 = statement("succession", k1, endorser=x, signers=[x, k1], activated_at=T0, created_at=T3)
    from_k0 = statement("succession", y, endorser=k0, signers=[k0, y], activated_at=T3, created_at=T3)
    trust = compute_key_trust(
        keys=[row(k0, T0, T1), row(k1, T0, T2), row(a, T1), row(x, T0), row(y, T3)],
        statements=[*history, into_k1, from_k0],
        trust_anchors=[f"sha256:{a.digest}"],
    )
    assert sorted(trust.trusted) == [a.digest]
    assert k1.digest in trust.undecided
    assert x.digest not in trust.undecided
    # An entry key's grade follows: the anchor anchored, the opaque key it
    # reaches undecided (CHAIN_UNSUPPORTED_ALGORITHM), anything else unanchored.
    cache = KeyCache({k.kid: RegisteredKey(spki_base64=k.public_key, source="embedded") for k in (a, k1, x)})
    marked = apply_key_trust(cache, trust).trust_states()
    assert (marked[a.kid], marked[k1.kid], marked[x.kid]) == ("anchored", "undecided", "unanchored")


@pytest.mark.usefixtures("fips_host")
def test_a_computable_key_is_not_left_undecided_because_an_opaque_half_on_its_path_cannot_be_checked() -> None:
    k0, _k1, a, history = _fips_history()
    # An ES256 key admitted by bytes under K0 that nothing here can check.
    y = make_key("ES256")
    from_k0 = statement("succession", y, endorser=k0, signers=[k0, y], activated_at=T3, created_at=T3)
    trust = compute_key_trust(keys=[], statements=[*history, from_k0], trust_anchors=[f"sha256:{a.digest}"])
    assert k0.digest in trust.undecided
    assert y.digest not in trust.undecided
    assert sorted(trust.trusted) == [a.digest]


# --- an all-zero key statement signature ---


def _zeroed(sign1: bytes) -> bytes:
    tag = cbor2.loads(sign1)
    p, u, payload, sig = tag.value
    return cbor2.dumps(cbor2.CBORTag(18, [p, dict(u), payload, bytes(len(sig))]), canonical=True)


def test_an_all_zero_statement_signature_is_refused_even_where_the_backend_would_accept_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OpenSSL rejects an all-zero signature on its own, but a verifier that
    accepts small-order Ed25519 points would not, so the walk does not lean on
    the backend for it. Simulated with a verify() that accepts any all-zero
    signature; everything else is real."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ed_type = type(Ed25519PrivateKey.generate().public_key())
    ec_type = type(ec.generate_private_key(ec.SECP256R1()).public_key())
    real_ed, real_ec = ed_type.verify, ec_type.verify

    def ed_verify(self: Any, signature: bytes, data: bytes) -> None:
        if signature and all(b == 0 for b in signature):
            return
        real_ed(self, signature, data)

    def ec_verify(self: Any, signature: bytes, data: bytes, algorithm: Any) -> None:
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        try:
            if decode_dss_signature(signature) == (0, 0):
                return
        except ValueError:
            pass
        real_ec(self, signature, data, algorithm)

    monkeypatch.setattr(ed_type, "verify", ed_verify)
    monkeypatch.setattr(ec_type, "verify", ec_verify)
    for alg in ("Ed25519", "ES256"):
        c = make_key(alg)  # type: ignore[arg-type]
        g = statement("genesis", c, signers=[c])

        def walk(cose: list[bytes], g: Any = g, c: Any = c) -> Any:
            import dataclasses

            return compute_key_trust(
                keys=[], statements=[dataclasses.replace(g, cose=cose)], trust_anchors=[f"sha256:{c.digest}"]
            )

        assert walk(list(g.cose)).findings == []
        forged = walk([_zeroed(bytes(g.cose[0]))])
        assert [(f.code, f.statement_id) for f in forged.findings] == [("KEY_STATEMENT_INVALID", g.id)]
        assert (forged.statements.valid, forged.statements.invalid) == (0, 1)
