"""The key-statement trust walk, ported case for case from verify-core's
``key-statements.test.ts`` (itself ported from the engine's), so the three are
held to the same behaviour. Registry findings carry the verifier codes:
key_statement_invalid is KEY_STATEMENT_INVALID, key_closure_invalid is
KEY_CLOSURE_INVALID, key_window_drift is CHAIN_KEY_WINDOW_DRIFT."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import cbor2
import pytest

from agledger.verify.key_statements import (
    DistrustedKey,
    KeyStatementInput,
    KeyTrust,
    TrustKeyInput,
    compute_key_trust,
    key_statements_from_export,
    parse_distrusted_keys,
    parse_trust_anchors,
)
from agledger.verify.verify_export import KeyCache, RegisteredKey, apply_key_trust

from .key_statement_helpers import (
    CTY,
    T0,
    T1,
    T2,
    T3,
    Stored,
    TestKey,
    as_document,
    as_published,
    encode_payload,
    envelope,
    make_key,
    next_id,
    raw_sign,
    row,
    sign_statement,
    statement,
)


def walk(
    keys: list[TrustKeyInput],
    statements: list[Any],
    anchors: list[str],
    distrusted: list[DistrustedKey] | None = None,
) -> KeyTrust:
    return compute_key_trust(
        keys=keys,
        statements=statements,
        trust_anchors=[f"sha256:{d}" for d in anchors],
        distrusted_keys=distrusted,
    )


def anchored_kids(trust: KeyTrust) -> list[str]:
    return sorted(d[:16] for d in trust.trusted)


def codes(trust: KeyTrust) -> list[tuple[str, str | None]]:
    return [(f.code, f.statement_id) for f in trust.findings]


def _flip_last(b: bytes) -> bytes:
    return b[:-1] + bytes([b[-1] ^ 0xFF])


# --- key statement trust walk ---


def test_a_rolling_key_change_anchors_both_keys_from_either_side() -> None:
    c, n = make_key(), make_key()
    genesis = statement("genesis", c, signers=[c], activated_at=T0)
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    for anchor in (c, n):
        trust = walk([row(c, T0), row(n, T1)], [genesis, succ], [anchor.digest])
        assert anchored_kids(trust) == sorted([c.kid, n.kid])
        assert trust.findings == []
        assert trust.by_digest[n.digest].activated_at == T1
        assert trust.by_digest[c.digest].activated_at == T0


def test_after_a_routine_closure_both_pins_reach_both_keys_and_the_closed_key_carries_the_signed_window() -> None:
    c, n = make_key(), make_key()
    genesis = statement("genesis", c, signers=[c])
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    closure = statement("closure", c, endorser=n, signers=[n], retired_at=T2, created_at=T2)
    for anchor in (c, n):
        trust = walk([row(c, T0, T2), row(n, T1)], [genesis, succ, closure], [anchor.digest])
        assert anchored_kids(trust) == sorted([c.kid, n.kid])
        assert trust.by_digest[c.digest].retired_at == T2
        assert trust.findings == []


def test_a_planted_key_with_its_own_genesis_stays_unanchored_and_the_statement_is_a_finding() -> None:
    c, x = make_key(), make_key()
    genesis = statement("genesis", c, signers=[c])
    planted = statement("genesis", x, signers=[x])
    trust = walk([row(c, T0), row(x, T0)], [genesis, planted], [c.digest])
    assert anchored_kids(trust) == [c.kid]
    assert codes(trust) == [("KEY_STATEMENT_INVALID", planted.id)]


def test_forged_successions_naming_the_real_endorser_stay_unanchored_and_each_is_a_finding() -> None:
    c, x = make_key(), make_key()
    genesis = statement("genesis", c, signers=[c])
    self_only = statement("succession", x, endorser=c, signers=[x])
    wrong_signer = statement("succession", x, endorser=c, signers=[x, x])
    garbage = statement("succession", x, endorser=c, signers=[c, x])
    garbage = replace(garbage, cose=[_flip_last(bytes(garbage.cose[0])), garbage.cose[1]])
    trust = walk([row(c, T0), row(x, T0)], [genesis, self_only, wrong_signer, garbage], [c.digest])
    assert anchored_kids(trust) == [c.kid]
    assert sorted(f.statement_id or "" for f in trust.findings if f.code == "KEY_STATEMENT_INVALID") == sorted(
        [self_only.id or "", wrong_signer.id or "", garbage.id or ""]
    )


def test_a_column_that_differs_from_the_signed_value_is_drift_compared_at_millisecond_precision() -> None:
    k, r = make_key(), make_key()
    genesis = statement("genesis", r, signers=[r], activated_at="2026-09-01T00:00:00.123456Z", created_at=T0)
    succ = statement("succession", k, endorser=r, signers=[r, k], activated_at=T1, created_at=T1)
    close = statement("closure", r, endorser=k, signers=[k], retired_at=T2, created_at=T2)
    # The honest dump column is the signed instant truncated to the millisecond.
    honest = walk([row(k, T1), row(r, "2026-09-01T00:00:00.123456Z", T2)], [genesis, succ, close], [k.digest])
    assert honest.findings == []
    drifted = replace(row(r, T0, T2), activated_at="2026-08-01T00:00:00.000Z")
    trust = walk([row(k, T1), drifted], [genesis, succ, close], [k.digest])
    assert anchored_kids(trust) == sorted([k.kid, r.kid])
    entry = trust.by_digest[r.digest]
    assert (entry.activated_at, entry.retired_at) == ("2026-09-01T00:00:00.123456Z", T2)
    assert [(f.code, f.key_id) for f in trust.findings] == [("CHAIN_KEY_WINDOW_DRIFT", r.kid)]


def test_a_statement_of_a_kind_outside_the_three_is_a_finding_and_admits_nothing() -> None:
    k, r = make_key(), make_key()
    genesis = statement("genesis", k, signers=[k], created_at=T1)
    unknown = statement("adoption", r, endorser=k, signers=[k], activated_at=T0, retired_at=T0, created_at=T2)
    trust = walk([row(r, T0, T0)], [genesis, unknown], [k.digest])
    assert anchored_kids(trust) == [k.kid]
    assert [(f.code, f.statement_id, f.detail) for f in trust.findings] == [
        ("KEY_STATEMENT_INVALID", unknown.id, "the payload does not decode as a key statement"),
    ]


def test_a_retired_anchored_row_with_no_signed_retirement_is_key_closure_invalid() -> None:
    c = make_key()
    genesis = statement("genesis", c, signers=[c])
    trust = walk([row(c, T0, T2)], [genesis], [c.digest])
    assert [(f.code, f.key_id) for f in trust.findings] == [("KEY_CLOSURE_INVALID", c.kid)]
    assert trust.by_digest[c.digest].retired_at is None


def test_a_closure_by_an_unanchored_key_closes_nothing_and_counting_closures_end_the_window_at_the_earliest() -> None:
    c, n, x = make_key(), make_key(), make_key()
    genesis = statement("genesis", c, signers=[c])
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    by_stranger = statement("closure", c, endorser=x, signers=[x], retired_at=T0, forced=True)
    later = statement("closure", c, endorser=n, signers=[n], retired_at=T3, created_at=T3)
    earlier = statement("closure", c, endorser=n, signers=[n], retired_at=T2, created_at=T3)
    trust = walk([row(x, T0)], [genesis, succ, by_stranger, later, earlier], [c.digest])
    assert anchored_kids(trust) == sorted([c.kid, n.kid])
    assert trust.by_digest[c.digest].retired_at == T2
    assert codes(trust) == [("KEY_CLOSURE_INVALID", by_stranger.id)]


def test_crosses_algorithms_an_ed25519_key_hands_over_to_an_es256_key() -> None:
    c, n = make_key(), make_key("ES256")
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    trust = walk([row(c, T0), row(n, T1)], [succ], [n.digest])
    assert anchored_kids(trust) == sorted([c.kid, n.kid])


def test_a_second_admission_is_a_finding_dates_nothing_earlier_and_cuts_the_keys_edge_back() -> None:
    c, n = make_key(), make_key()
    genesis = statement("genesis", c, signers=[c], created_at=T0)
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1)
    redate = statement("genesis", n, signers=[n], activated_at=T0, created_at=T2)
    from_c = walk([], [genesis, succ, redate], [c.digest])
    assert anchored_kids(from_c) == sorted([c.kid, n.kid])
    assert from_c.by_digest[n.digest].activated_at == T1
    assert codes(from_c) == [("KEY_STATEMENT_INVALID", redate.id)]
    assert anchored_kids(walk([], [genesis, succ, redate], [n.digest])) == [n.kid]


def test_a_signature_under_a_cose_alg_the_statement_format_does_not_use_is_refused() -> None:
    # The chain envelope accepts -19 for Ed25519; a statement carries -8 only.
    c = make_key()
    g = statement("genesis", c, signers=[c])
    data = encode_payload(g.payload)
    good = sign_statement(data, c)
    protected = cbor2.dumps({1: -19, 3: CTY, 4: bytes.fromhex(c.kid)}, canonical=True)
    tbs = cbor2.dumps(["Signature1", protected, b"", data], canonical=True)
    bad = envelope(protected, data, raw_sign(c, tbs))
    assert walk([], [replace(g, cose=[good])], [c.digest]).findings == []
    assert codes(walk([], [replace(g, cose=[bad])], [c.digest])) == [("KEY_STATEMENT_INVALID", g.id)]


# --- each statement check holds on its own ---
#
# Every statement below is signed for real; each breaks exactly one rule,
# beside a twin that keeps it and walks clean.


def _genesis_payload(k: TestKey, **over: Any) -> dict[str, Any]:
    subject = {"kid": k.kid, "spkiSha256": k.digest, "alg": k.alg, "spki": k.public_key, "activatedAt": T0, **over}
    return {"typ": "genesis", "iss": "https://ledger.example", "subject": subject, "iat": 1}


def _filed(kind: str, subject_key_id: str, cose: list[bytes]) -> KeyStatementInput:
    return KeyStatementInput(id=next_id(), kind=kind, subject_key_id=subject_key_id, cose=cose)


def _refused(k: TestKey, st: KeyStatementInput) -> None:
    assert codes(walk([], [st], [k.digest])) == [("KEY_STATEMENT_INVALID", st.id)]


def _clean(k: TestKey, st: KeyStatementInput) -> None:
    assert walk([], [st], [k.digest]).findings == []


def test_the_protected_header_carries_the_key_statement_content_type() -> None:
    c = make_key()
    data = encode_payload(_genesis_payload(c))
    _clean(c, _filed("genesis", c.kid, [sign_statement(data, c)]))
    _refused(c, _filed("genesis", c.kid, [sign_statement(data, c, cty="application/cbor")]))
    _refused(c, _filed("genesis", c.kid, [sign_statement(data, c, cty=60)]))


def test_the_protected_header_names_the_key_that_signed() -> None:
    c, other = make_key(), make_key()
    _refused(c, _filed("genesis", c.kid, [sign_statement(encode_payload(_genesis_payload(c)), c, kid=other.kid)]))


def test_the_payload_is_deterministic_cbor_the_same_map_in_another_key_order_is_refused() -> None:
    c = make_key()
    canonical = encode_payload(_genesis_payload(c))
    decoded = cbor2.loads(canonical)
    reordered = cbor2.dumps(dict(reversed(list(decoded.items()))))
    assert reordered != canonical
    assert cbor2.loads(reordered) == decoded
    _clean(c, _filed("genesis", c.kid, [sign_statement(canonical, c)]))
    _refused(c, _filed("genesis", c.kid, [sign_statement(reordered, c)]))


def test_the_subject_kid_is_its_spki_fingerprint() -> None:
    c = make_key()
    kid = "bbbbbbbbbbbbbbbb" if c.kid == "aaaaaaaaaaaaaaaa" else "aaaaaaaaaaaaaaaa"
    _refused(c, _filed("genesis", kid, [sign_statement(encode_payload(_genesis_payload(c, kid=kid)), c, kid=kid)]))


def test_the_subject_alg_names_the_algorithm_its_spki_commits_to() -> None:
    c = make_key()
    _refused(c, _filed("genesis", c.kid, [sign_statement(encode_payload(_genesis_payload(c, alg="ES256")), c)]))
    e = make_key("ES256")
    _clean(e, _filed("genesis", e.kid, [sign_statement(encode_payload(_genesis_payload(e)), e)]))
    _refused(e, _filed("genesis", e.kid, [sign_statement(encode_payload(_genesis_payload(e, alg="Ed25519")), e)]))


def test_a_statement_carries_exactly_the_signatures_its_kind_takes() -> None:
    c, n = make_key(), make_key()
    data = encode_payload(_genesis_payload(c))
    _refused(c, _filed("genesis", c.kid, [sign_statement(data, c), sign_statement(data, c)]))
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    extra = replace(succ, cose=[*succ.cose, succ.cose[1]])
    assert walk([], [statement("genesis", c, signers=[c]), succ], [c.digest]).findings == []
    assert codes(walk([], [extra], [c.digest])) == [("KEY_STATEMENT_INVALID", extra.id)]


def test_the_kind_a_statement_is_filed_under_is_the_kind_it_signs() -> None:
    c = make_key()
    g = statement("genesis", c, signers=[c])
    assert walk([], [g], [c.digest]).findings == []
    for kind in ("succession", "closure"):
        assert codes(walk([], [replace(g, kind=kind)], [c.digest])) == [("KEY_STATEMENT_INVALID", g.id)]


def test_a_succession_does_not_endorse_its_own_key_and_a_closure_is_not_signed_by_the_key_it_closes() -> None:
    c = make_key()
    self_succ = statement("succession", c, endorser=c, signers=[c, c], activated_at=T1)
    assert codes(walk([], [self_succ], [c.digest])) == [("KEY_STATEMENT_INVALID", self_succ.id)]
    self_close = statement("closure", c, endorser=c, signers=[c], retired_at=T2)
    trust = walk([row(c, T0)], [self_close], [c.digest])
    assert codes(trust) == [("KEY_STATEMENT_INVALID", self_close.id)]
    assert trust.by_digest[c.digest].retired_at is None


# --- a leaked key ---


def _history() -> tuple[TestKey, TestKey, Stored, Stored]:
    c, n = make_key(), make_key()
    genesis = statement("genesis", c, signers=[c], created_at=T0)
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1)
    return c, n, genesis, succ


def test_leaked_after_a_routine_retirement_cannot_admit_a_key_whatever_time_it_claims_from_any_pin() -> None:
    c, n, genesis, succ = _history()
    x = make_key()
    closure = statement("closure", c, endorser=n, signers=[n], retired_at=T2, created_at=T2)
    t0_seconds = int(datetime(2026, 9, 1, tzinfo=UTC).timestamp())
    leak = statement("succession", x, endorser=c, signers=[c, x], activated_at=T0, iat=t0_seconds, created_at=T3)
    for anchor in (c, n):
        trust = walk([], [genesis, succ, closure, leak], [anchor.digest])
        assert anchored_kids(trust) == sorted([c.kid, n.kid])
        assert codes(trust) == [("KEY_STATEMENT_INVALID", leak.id)]


_A = "2026-09-02T06:00:00.000000Z"
_B = "2026-09-02T12:00:00.000000Z"
_C = "2026-09-02T18:00:00.000000Z"


@pytest.mark.parametrize(
    ("by_n", "by_x", "expected"),
    [
        pytest.param([{"retired_at": _C}], {"retired_at": _B}, True, id="earlier than the one published closure"),
        pytest.param([{"retired_at": _B}], {"retired_at": _B}, False, id="as the published closure dates it"),
        pytest.param([{"retired_at": _B}], {"retired_at": _C}, False, id="later than the published closure"),
        pytest.param([{"retired_at": _C}, {"retired_at": _A}], {"retired_at": _B}, False, id="between two published closures"),
        pytest.param([{"retired_at": _C}, {"retired_at": _B}], {"retired_at": _A}, True, id="earlier than both published closures"),
        pytest.param([{"retired_at": _B}], {"retired_at": _B, "forced": True}, True, id="forced where no published closure is"),
        pytest.param([{"retired_at": _B, "forced": True}], {"retired_at": _B, "forced": True}, False, id="forced as a published closure is"),
        pytest.param(
            [{"retired_at": _B}, {"retired_at": _B, "forced": True}],
            {"retired_at": _B, "forced": True},
            False,
            id="forced as one of two published closures is",
        ),
    ],
)
def test_a_counting_closure_by_a_key_reached_but_not_anchored_is_a_finding_and_says_when_it_moves_the_window(
    by_n: list[dict[str, Any]], by_x: dict[str, Any], expected: bool
) -> None:
    c, n, genesis, succ = _history()
    x = make_key()
    from_n = [
        statement("closure", c, endorser=n, signers=[n], created_at=f"2026-09-03T0{i}:00:00.000000Z", **cl)
        for i, cl in enumerate(by_n)
    ]
    leak = statement("succession", x, endorser=c, signers=[c, x], activated_at=T3, created_at=T3)
    from_x = statement("closure", c, endorser=x, signers=[x], created_at="2026-09-05T00:00:00.000000Z", **by_x)
    trust = walk([], [genesis, succ, *from_n, leak, from_x], [n.digest])
    assert c.digest in trust.trusted and x.digest not in trust.trusted
    on_x = [f for f in trust.findings if f.statement_id == from_x.id]
    assert [f.code for f in on_x] == ["KEY_CLOSURE_INVALID"]
    assert "reached but not anchored" in on_x[0].detail
    assert f"pin sha256:{x.digest} in trustAnchors" in on_x[0].detail
    assert f"distrustedKeys sha256:{x.digest}@{from_x.created_at}" in on_x[0].detail
    moved = "earlier than any closure a published key signs" in on_x[0].detail or (
        "which no closure a published key signs does" in on_x[0].detail
    )
    assert moved == expected


def test_the_published_admission_of_a_trusted_key_whose_endorser_a_forced_closure_cut_off_is_a_finding_until_pinned() -> None:
    a, b, d = make_key(), make_key(), make_key()
    genesis = statement("genesis", a, signers=[a], created_at=T0)
    admit_b = statement("succession", b, endorser=a, signers=[a, b], activated_at=T1, created_at=T1)
    admit_d = statement("succession", d, endorser=b, signers=[b, d], activated_at=T2, created_at=T2)
    forced = statement("closure", b, endorser=d, signers=[d], retired_at=T3, forced=True, created_at=T3)
    statements = [genesis, admit_b, admit_d, forced]
    trust = walk([], statements, [d.digest])
    assert anchored_kids(trust) == sorted([b.kid, d.kid])
    on_admission = [f for f in trust.findings if f.statement_id == admit_b.id]
    assert [f.code for f in on_admission] == ["KEY_STATEMENT_INVALID"]
    assert f"pin sha256:{a.digest} in trustAnchors" in on_admission[0].detail
    assert [f for f in walk([], statements, [d.digest, a.digest]).findings if f.statement_id == admit_b.id] == []
    # A distrusted endorser is never offered as a pin.
    distrusted = walk([], statements, [d.digest], [DistrustedKey(a.digest, T3)])
    assert [f.code for f in distrusted.findings if f.statement_id == admit_b.id] == ["KEY_STATEMENT_INVALID"]
    assert all(f"pin sha256:{a.digest}" not in f.detail for f in distrusted.findings)


def test_leaked_cannot_admit_a_key_by_signing_it_in_as_its_own_predecessor_retired_or_not() -> None:
    c, n, genesis, succ = _history()
    x = make_key()
    closure = statement("closure", c, endorser=n, signers=[n], retired_at=T2, created_at=T2)
    back = statement("succession", c, endorser=x, signers=[x, c], created_at=T3)
    for statements in ([genesis, succ, back], [genesis, succ, closure, back]):
        trust = walk([row(x, T3)], statements, [n.digest])
        assert anchored_kids(trust) == sorted([c.kid, n.kid])
        assert codes(trust) == [("KEY_STATEMENT_INVALID", back.id)]


def test_leaked_before_detection_admits_a_key_and_a_forced_retirement_voids_everything_it_admitted() -> None:
    c, n, genesis, succ = _history()
    x, y = make_key(), make_key()
    leak = statement("succession", x, endorser=c, signers=[c, x], created_at=T1)
    onward = statement("succession", y, endorser=x, signers=[x, y], created_at=T2)
    before = walk([], [genesis, succ, leak, onward], [n.digest])
    assert anchored_kids(before) == sorted([c.kid, n.kid, x.kid, y.kid])

    forced = statement("closure", c, endorser=n, signers=[n], retired_at=T2, forced=True, created_at=T3)
    after = walk([], [genesis, succ, leak, onward, forced], [n.digest])
    assert anchored_kids(after) == sorted([c.kid, n.kid])
    entry = after.by_digest[c.digest]
    assert (entry.activated_at, entry.retired_at) == (T0, T2)
    assert [f for f in after.findings if f.statement_id == leak.id] == []
    assert anchored_kids(walk([], [genesis, succ, leak, onward, forced], [c.digest])) == [c.kid]


def test_anchored_with_no_admission_cannot_keep_a_key_it_signed_in_as_its_predecessor_past_a_forced_retirement() -> None:
    p, n, x = make_key(), make_key(), make_key()
    succ = statement("succession", n, endorser=p, signers=[p, n], activated_at=T1, created_at=T1)
    back = statement("succession", p, endorser=x, signers=[x, p], activated_at=T0, created_at=T2)
    forced = statement("closure", p, endorser=n, signers=[n], retired_at=T2, forced=True, created_at=T3)
    assert anchored_kids(walk([row(x, T0)], [succ, back], [n.digest])) == sorted([n.kid, p.kid, x.kid])
    for pin, want in ((n, [n.kid, p.kid]), (p, [p.kid])):
        assert anchored_kids(walk([row(x, T0)], [succ, back, forced], [pin.digest])) == sorted(want)


def test_leaked_closes_keys_only_to_take_trust_away() -> None:
    c, n, genesis, succ = _history()
    m, x = make_key(), make_key()
    succ_m = statement("succession", m, endorser=n, signers=[n, m], activated_at=T2, created_at=T2)
    close_n = statement("closure", n, endorser=c, signers=[c], retired_at=T1, forced=True, created_at=T3)
    leak = statement("succession", x, endorser=c, signers=[c, x], created_at=T3)
    forced = statement("closure", c, endorser=m, signers=[m], retired_at=T3, forced=True, created_at=T3)
    honest = walk([], [genesis, succ, succ_m, forced], [m.digest])
    attacked = walk([], [genesis, succ, succ_m, close_n, leak, forced], [m.digest])
    assert anchored_kids(honest) == sorted([c.kid, n.kid, m.kid])
    assert anchored_kids(attacked) == sorted([n.kid, m.kid])
    assert attacked.by_digest[n.digest].retired_at == T1
    assert anchored_kids(walk([], [genesis, succ, succ_m, close_n, leak, forced], [n.digest])) == [n.kid]


def test_leaked_before_registration_cannot_pull_a_key_in_through_an_admission_stored_ahead_of_the_honest_one() -> None:
    h, k, a = make_key(), make_key(), make_key()
    genesis = statement("genesis", h, signers=[h], created_at=T0)
    early = statement(
        "succession", k, endorser=a, signers=[a, k], activated_at="2000-01-01T00:00:00.000000Z", created_at=T1
    )
    honest = statement("succession", k, endorser=h, signers=[h, k], activated_at=T2, created_at=T2)
    forced = statement("closure", k, endorser=h, signers=[h], retired_at=T3, forced=True, created_at=T3)
    for statements in ([genesis, early, honest], [genesis, early, honest, forced]):
        for pin in (h, k):
            trust = walk([row(a, T0)], statements, [pin.digest])
            assert a.kid not in anchored_kids(trust)
            assert trust.by_digest[k.digest].activated_at == T2


def test_keeps_rows_stored_in_the_same_millisecond_in_write_order() -> None:
    c, n, genesis, succ = _history()
    x = make_key()
    closure = statement("closure", c, endorser=n, signers=[n], retired_at=T2, created_at=T2)
    leak = statement("succession", x, endorser=c, signers=[c, x], created_at=T2)
    assert anchored_kids(walk([], [genesis, succ, closure, leak], [n.digest])) == sorted([c.kid, n.kid])


# --- distrusted keys (the Server's VAULT_DISTRUSTED_KEYS) ---

EPOCH_ZERO = "1970-01-01T00:00:00.000000Z"


def test_distrusted_retired_and_leaked_its_closure_of_the_key_that_retired_it_counts_until_it_is_distrusted() -> None:
    r, h, h2 = make_key(), make_key(), make_key()
    statements = [
        statement("genesis", r, signers=[r], activated_at=T0, created_at=T0),
        statement("succession", h, endorser=r, signers=[r, h], activated_at=T1, created_at=T1),
        statement("closure", r, endorser=h, signers=[h], retired_at=T2, created_at=T2),
    ]
    evil = statement("closure", h, endorser=r, signers=[r], retired_at=EPOCH_ZERO, forced=True, created_at=T3)
    statements += [
        evil,
        statement("closure", r, endorser=h, signers=[h], retired_at=T2, forced=True, created_at=T3),
        statement("succession", h2, endorser=h, signers=[h, h2], activated_at=T3, created_at=T3),
    ]
    for pin in (h, h2):
        attacked = walk([], statements, [pin.digest])
        assert attacked.by_digest[h.digest].retired_at == EPOCH_ZERO
        assert any(
            f.code == "KEY_CLOSURE_INVALID" and f.statement_id == evil.id and f"distrustedKeys sha256:{r.digest}" in f.detail
            for f in attacked.findings
        )
        healed = walk([], statements, [pin.digest], [DistrustedKey(r.digest, None)])
        entry = healed.by_digest[h.digest]
        assert (entry.activated_at, entry.retired_at) == (T1, None)
        assert healed.by_digest[r.digest].trusted is True
        assert healed.by_digest[r.digest].retired_at == T2
        assert any(
            f.code == "KEY_CLOSURE_INVALID" and f.statement_id == evil.id and "distrustedKeys" in f.detail
            for f in healed.findings
        )


def test_distrusted_keeps_what_it_signed_before_its_cutoff() -> None:
    p, d, n, x = make_key(), make_key(), make_key(), make_key()
    leak = statement("succession", x, endorser=d, signers=[d, x], activated_at=T0, created_at=T3)
    trust = walk(
        [],
        [
            statement("genesis", p, signers=[p], activated_at=T0, created_at=T0),
            statement("succession", d, endorser=p, signers=[p, d], activated_at=T0, created_at=T0),
            statement("closure", p, endorser=d, signers=[d], retired_at=T1, created_at=T1),
            statement("succession", n, endorser=d, signers=[d, n], activated_at=T1, created_at=T1),
            statement("closure", d, endorser=n, signers=[n], retired_at=T2, created_at=T2),
            leak,
        ],
        [n.digest],
        [DistrustedKey(d.digest, None)],
    )
    assert anchored_kids(trust) == sorted([p.kid, d.kid, n.kid])
    assert trust.by_digest[p.digest].retired_at == T1
    assert trust.by_digest[d.digest].retired_at == T2
    assert codes(trust) == [("KEY_STATEMENT_INVALID", leak.id)]


def test_distrusted_with_an_instant_ends_its_window_there_and_with_none_trusts_it_for_nothing() -> None:
    c, n, m = make_key(), make_key(), make_key()
    succ_m = statement("succession", m, endorser=n, signers=[n, m], activated_at=T2, created_at=T2)
    statements = [
        statement("genesis", c, signers=[c], activated_at=T0, created_at=T0),
        statement("succession", n, endorser=c, signers=[c, n], activated_at=T0, created_at=T0),
        succ_m,
    ]
    cut = walk([row(n, T0)], statements, [c.digest], [DistrustedKey(n.digest, T1)])
    assert anchored_kids(cut) == sorted([c.kid, n.kid])
    entry = cut.by_digest[n.digest]
    # The cutoff ends the window without retiring the key.
    assert (entry.activated_at, entry.retired_at, entry.distrust_cutoff) == (T0, None, T1)
    applied = apply_key_trust(KeyCache({n.kid: RegisteredKey(n.public_key, "embedded")}), cut).entry(n.kid)
    assert applied is not None
    assert (applied.trust, applied.activated_at, applied.retired_at, applied.distrust_cutoff) == ("anchored", T0, None, T1)
    # With no retirement by a trusted key, nothing bounds what the entry
    # accounts for: the succession n stored after its cutoff stays a finding,
    # and so does n's registry row.
    assert codes(cut) == [("KEY_STATEMENT_INVALID", succ_m.id), ("KEY_CLOSURE_INVALID", None)]
    assert f"POST /v1/admin/vault/signing-keys/{n.kid}/retire" in cut.findings[1].detail
    assert cut.accounted == []
    assert anchored_kids(walk([], statements, [c.digest], [DistrustedKey(n.digest, None)])) == [c.kid]


def test_distrusted_names_the_key_a_dropped_closure_reopens() -> None:
    o, p, a, b, q = make_key(), make_key(), make_key(), make_key(), make_key()
    leak_at = "2026-09-02T06:00:00.000000Z"

    def at(h: int) -> str:
        return f"2026-09-02T{h:02d}:00:00.000000Z"

    statements = [
        statement("genesis", o, signers=[o], activated_at=T0, created_at=T0),
        statement("succession", p, endorser=o, signers=[o, p], activated_at=T0, created_at=T0),
        statement("closure", o, endorser=p, signers=[p], retired_at=T1, created_at=T1),
        statement("succession", a, endorser=p, signers=[p, a], activated_at=T1, created_at=T1),
        statement("closure", p, endorser=a, signers=[a], retired_at=at(12), forced=True, created_at=at(12)),
        statement("succession", q, endorser=p, signers=[p, q], activated_at=at(13), created_at=at(13)),
        statement("succession", b, endorser=a, signers=[a, b], activated_at=at(14), created_at=at(14)),
        statement("closure", a, endorser=b, signers=[b], retired_at=at(15), created_at=at(15)),
    ]
    only_a = walk([], statements, [b.digest], [DistrustedKey(a.digest, leak_at)])
    assert any(
        f.code == "KEY_CLOSURE_INVALID" and f"add sha256:{p.digest} to distrustedKeys too" in f.detail
        for f in only_a.findings
    )
    both = walk([], statements, [b.digest], [DistrustedKey(a.digest, leak_at), DistrustedKey(p.digest, leak_at)])
    assert q.digest not in both.trusted
    assert (both.by_digest[p.digest].retired_at, both.by_digest[p.digest].distrust_cutoff) == (None, leak_at)


def test_distrusted_does_not_blame_an_honest_closure_when_its_subjects_leaked_half_redates_it_later() -> None:
    a, b = make_key(), make_key()
    trust = walk(
        [],
        [
            statement("genesis", a, signers=[a], activated_at=T0, created_at=T0),
            statement("succession", b, endorser=a, signers=[a, b], activated_at=T1, created_at=T1),
            statement("closure", a, endorser=b, signers=[b], retired_at=T2, created_at=T2),
            statement("genesis", a, signers=[a], activated_at=T3, created_at=T3),
        ],
        [b.digest],
    )
    assert [f for f in trust.findings if f.code == "KEY_CLOSURE_INVALID"] == []


def test_distrusted_is_dated_only_by_a_key_reached_without_it() -> None:
    c, d, x = make_key(), make_key(), make_key()
    trust = walk(
        [],
        [
            statement("genesis", c, signers=[c], activated_at=T0, created_at=T0),
            statement("succession", d, endorser=c, signers=[c, d], activated_at=T0, created_at=T0),
            statement("succession", x, endorser=d, signers=[d, x], created_at=T1),
            statement("closure", d, endorser=x, signers=[x], retired_at=EPOCH_ZERO, created_at=T1),
        ],
        [c.digest],
        [DistrustedKey(d.digest, None)],
    )
    assert anchored_kids(trust) == [c.kid]


def test_the_cutoff_of_a_distrusted_key_with_no_instant_is_the_earliest_counting_retirement() -> None:
    a, d, x = make_key(), make_key(), make_key()
    t2b = "2026-09-03T12:00:00.000000Z"
    statements = [
        statement("genesis", a, signers=[a], activated_at=T0, created_at=T0),
        statement("succession", d, endorser=a, signers=[a, d], activated_at=T0, created_at=T0),
        # Stored before either closure, and inside d's later retirement but not its earlier one.
        statement("succession", x, endorser=d, signers=[d, x], activated_at=T2, created_at=T2),
        statement("closure", d, endorser=a, signers=[a], retired_at=T1, created_at=T3),
        statement("closure", d, endorser=a, signers=[a], retired_at=t2b, created_at=T3),
    ]
    assert x.digest in walk([], statements, [a.digest]).trusted
    trust = walk([], statements, [a.digest], [DistrustedKey(d.digest, None)])
    assert x.digest not in trust.trusted
    assert trust.by_digest[d.digest].retired_at == T1


def test_the_cutoff_of_a_distrusted_key_is_never_dated_by_a_closure_another_distrusted_key_signed() -> None:
    a, d, e = make_key(), make_key(), make_key()
    statements = [
        statement("genesis", a, signers=[a], activated_at=T0, created_at=T0),
        statement("succession", d, endorser=a, signers=[a, d], activated_at=T0, created_at=T0),
        statement("succession", e, endorser=a, signers=[a, e], activated_at=T0, created_at=T0),
        statement("closure", d, endorser=e, signers=[e], retired_at=T1, created_at=T1),
    ]
    trust = walk([], statements, [a.digest], [DistrustedKey(d.digest, None), DistrustedKey(e.digest, T3)])
    # e's closure counts as a closure, but it cannot vouch for when d stopped counting.
    assert d.digest not in trust.trusted
    assert e.digest in trust.trusted
    # Distrust e from the start of time and the closure is still no date for d.
    again = walk([], statements, [a.digest], [DistrustedKey(d.digest, None), DistrustedKey(e.digest, T0)])
    assert d.digest not in again.trusted


def test_a_key_admitted_only_by_a_distrusted_key_cannot_close_a_key() -> None:
    a, d, x, y = make_key(), make_key(), make_key(), make_key()
    closure = statement("closure", y, endorser=x, signers=[x], retired_at=T3, created_at=T3)
    statements = [
        statement("genesis", a, signers=[a], activated_at=T0, created_at=T0),
        statement("succession", d, endorser=a, signers=[a, d], activated_at=T0, created_at=T0),
        statement("succession", y, endorser=a, signers=[a, y], activated_at=T0, created_at=T0),
        statement("succession", x, endorser=d, signers=[d, x], activated_at=T2, created_at=T2),
        closure,
    ]
    assert walk([], statements, [a.digest]).by_digest[y.digest].retired_at == T3
    trust = walk([], statements, [a.digest], [DistrustedKey(d.digest, T1)])
    assert x.digest not in trust.trusted
    assert trust.by_digest[y.digest].retired_at is None
    assert [f.code for f in trust.findings if f.statement_id == closure.id] == ["KEY_CLOSURE_INVALID"]


def test_a_statement_row_that_holds_no_signature_is_a_finding_and_does_not_stop_the_walk() -> None:
    c = make_key()
    genesis = statement("genesis", c, signers=[c])
    empty = replace(genesis, id=next_id(), cose=[None])
    nested = replace(genesis, id=next_id(), cose=[[genesis.cose[0]]])
    trust = walk([row(c, T0)], [genesis, empty, nested], [c.digest])
    assert anchored_kids(trust) == [c.kid]
    assert sorted(codes(trust), key=lambda t: t[1] or "") == sorted(
        [("KEY_STATEMENT_INVALID", empty.id), ("KEY_STATEMENT_INVALID", nested.id)], key=lambda t: t[1] or ""
    )


# --- a walk over a key document (no write order) ---


def test_a_document_walk_orders_by_signed_instants_and_agrees_with_the_dump_on_an_honest_rotation() -> None:
    c, n, m = make_key(), make_key(), make_key()
    statements = [
        statement("genesis", c, signers=[c], activated_at=T0, created_at=T0),
        statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1),
        statement("closure", c, endorser=n, signers=[n], retired_at=T2, created_at=T2),
        statement("succession", m, endorser=n, signers=[n, m], activated_at=T2, created_at=T2),
        statement("closure", n, endorser=m, signers=[m], retired_at=T3, forced=False, created_at=T3),
    ]
    # A document lists each key's statements under it, newest key first.
    doc = as_document(list(reversed(statements)))
    for pin in (c, n, m):
        dump = walk([], statements, [pin.digest])
        from_doc = walk([], doc, [pin.digest])
        assert from_doc.order == "signed"
        assert dump.order == "written"
        assert anchored_kids(from_doc) == anchored_kids(dump) == sorted([c.kid, n.kid, m.kid])
        for d in (c, n, m):
            assert from_doc.by_digest[d.digest] == dump.by_digest[d.digest]
        assert from_doc.findings == []


def test_a_document_walk_orders_a_closure_after_a_succession_that_signs_the_same_instant() -> None:
    p, c = make_key(), make_key()
    g = statement("genesis", p, signers=[p], activated_at=T0)
    s = statement("succession", c, endorser=p, signers=[p, c], activated_at=T1)
    cl = statement("closure", p, endorser=c, signers=[c], retired_at=T1)
    for order in ([g, s, cl], [g, cl, s], [cl, s, g], [s, cl, g]):
        for pin in (p, c):
            trust = walk([row(p, T0, T1), row(c, T1)], as_document(order), [pin.digest])
            assert anchored_kids(trust) == sorted([p.kid, c.kid])
            assert trust.findings == []
            assert trust.by_digest[p.digest].retired_at == T1
    # One microsecond later, the succession is after the closure in any listing, and admits nothing.
    late = statement("succession", c, endorser=p, signers=[p, c], activated_at="2026-09-02T00:00:00.000001Z")
    for order in ([g, late, cl], [g, cl, late]):
        assert c.digest not in walk([], as_document(order), [p.digest]).trusted


def test_a_walk_counts_a_statement_listed_twice_once_a_dump_row_copied_under_another_id_included() -> None:
    c, n = make_key(), make_key()
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    # A copy repeats the signed payload, so it says nothing new, as the engine reads it.
    keys = [TrustKeyInput(key_id=c.kid, public_key=c.public_key)]
    for statements in ([succ, replace(succ, id=next_id())], as_document([succ, succ])):
        trust = walk(keys, statements, [n.digest])
        assert anchored_kids(trust) == sorted([c.kid, n.kid])
        assert trust.findings == []


def test_a_walk_refuses_statements_that_mix_a_write_time_with_none() -> None:
    c = make_key()
    g = statement("genesis", c, signers=[c])
    with pytest.raises(TypeError):
        walk([], [g, *as_document([g])], [c.digest])


def test_a_document_walk_voids_the_forward_edge_of_a_forced_closure_whatever_instant_the_leaked_key_signs() -> None:
    c, n, x = make_key(), make_key(), make_key()
    genesis = statement("genesis", c, signers=[c], activated_at=T0)
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    backdated = statement("succession", x, endorser=c, signers=[c, x], activated_at=T0)
    forced = statement("closure", c, endorser=n, signers=[n], retired_at=T2, forced=True)
    trust = walk([], as_document([genesis, succ, backdated, forced]), [n.digest])
    assert x.digest not in trust.trusted


# --- a walk over a key document that publishes write order ---


def _published(statements: list[Stored]) -> list[KeyStatementInput]:
    return key_statements_from_export(as_published(statements))


def test_a_published_document_is_walked_in_write_order_and_agrees_with_the_dump_on_an_honest_rotation() -> None:
    c, n, m = make_key(), make_key(), make_key()
    statements = [
        statement("genesis", c, signers=[c], activated_at=T0, created_at=T0),
        statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1),
        statement("closure", c, endorser=n, signers=[n], retired_at=T2, created_at=T2),
        statement("succession", m, endorser=n, signers=[n, m], activated_at=T2, created_at=T2),
        statement("closure", n, endorser=m, signers=[m], retired_at=T3, forced=False, created_at=T3),
    ]
    # Filed under each key, newest key first.
    doc = _published(list(reversed(statements)))
    assert {st.id for st in doc} == {st.id for st in statements}
    for pin in (c, n, m):
        dump = walk([], statements, [pin.digest])
        from_doc = walk([], doc, [pin.digest])
        assert from_doc.order == dump.order == "written"
        assert anchored_kids(from_doc) == anchored_kids(dump) == sorted([c.kid, n.kid, m.kid])
        for d in (c, n, m):
            assert from_doc.by_digest[d.digest] == dump.by_digest[d.digest]
        assert from_doc.findings == []


def test_a_published_document_orders_by_the_write_time_never_by_an_instant_a_statement_signs() -> None:
    p, c, x = make_key(), make_key(), make_key()
    g = statement("genesis", p, signers=[p], activated_at=T0, created_at=T0)
    s = statement("succession", c, endorser=p, signers=[p, c], activated_at=T1, created_at=T1)
    cl = statement("closure", p, endorser=c, signers=[c], retired_at=T2, created_at=T2)
    # Signs an activation before the closure, and was stored after it.
    late = statement("succession", x, endorser=p, signers=[p, x], activated_at=T1, created_at=T3)
    for order in ([g, s, cl, late], [late, cl, s, g], [cl, late, g, s]):
        trust = walk([], _published(order), [p.digest])
        assert trust.order == "written"
        assert anchored_kids(trust) == sorted([p.kid, c.kid])
        assert x.digest not in trust.trusted
    # The same document with the write times stripped falls back to the signed
    # order, where the backdated succession reads as before the closure.
    assert x.digest in walk([], as_document([g, s, cl, late]), [p.digest]).trusted


def test_two_statements_published_in_the_same_microsecond_are_ordered_by_id() -> None:
    p, c = make_key(), make_key()
    g = statement("genesis", p, signers=[p], activated_at=T0, created_at=T0)
    s = replace(statement("succession", c, endorser=p, signers=[p, c], activated_at=T1, created_at=T1), id="b")
    # Stored in the same microsecond as the succession, with the larger id: after it.
    cl = replace(statement("closure", p, endorser=c, signers=[c], retired_at=T1, created_at=T1), id="c")
    for order in ([g, s, cl], [cl, s, g]):
        trust = walk([], _published(order), [p.digest])
        assert anchored_kids(trust) == sorted([p.kid, c.kid])
        assert trust.findings == []
    # With the smaller id the closure is first, and the succession after it admits nothing.
    early = replace(cl, id="a")
    for order in ([g, s, early], [early, s, g]):
        assert c.digest not in walk([], _published(order), [p.digest]).trusted


def test_a_published_statement_with_no_strict_rfc3339_write_time_is_invalid_and_admits_nothing() -> None:
    c, n = make_key(), make_key()
    g = statement("genesis", c, signers=[c], activated_at=T0, created_at=T0)
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1)
    lenient = (
        "2026-09-01T00:00:00",
        "2026-09-01 00:00:00Z",
        "1",
        "2026-02-30T00:00:00.000000Z",
        "2026-09-01T24:00:00Z",
        "2026-09-01T00:00:00+24:00",
    )
    for broken in (None, 7, "yesterday", *lenient):
        filed = as_published([g, succ])
        if broken is None:
            del filed[n.kid][0]["createdAt"]
        else:
            filed[n.kid][0]["createdAt"] = broken
        doc = key_statements_from_export(filed)
        trust = walk([], doc, [c.digest])
        assert trust.order == "written"
        assert anchored_kids(trust) == [c.kid]
        assert codes(trust) == [("KEY_STATEMENT_INVALID", succ.id)]


def test_a_later_admission_a_document_publishes_dates_the_window_and_cuts_the_edge_back() -> None:
    c, n = make_key(), make_key()
    g = statement("genesis", c, signers=[c], activated_at=T0, created_at=T0)
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1)
    again = statement("genesis", n, signers=[n], activated_at=T2, created_at=T2)
    dump = walk([], [g, succ, again], [n.digest])
    from_doc = walk([], _published([g, succ, again]), [n.digest])
    assert anchored_kids(from_doc) == anchored_kids(dump) == [n.kid]
    assert from_doc.by_digest[n.digest].activated_at == dump.by_digest[n.digest].activated_at == T2


def test_a_published_row_listed_twice_is_one_row_and_so_is_a_copy_under_another_id_and_a_later_time() -> None:
    c, n = make_key(), make_key()
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1)
    keys = [TrustKeyInput(key_id=c.kid, public_key=c.public_key)]
    twice = as_published([succ])
    twice[n.kid] = twice[n.kid] * 2
    assert anchored_kids(walk(keys, key_statements_from_export(twice), [n.digest])) == sorted([c.kid, n.kid])
    copied = _published([succ, replace(succ, id=next_id(), created_at="2026-09-04T00:00:00.000000Z")])
    trust = walk(keys, copied, [n.digest])
    assert anchored_kids(trust) == sorted([c.kid, n.kid])
    assert trust.findings == []


def test_one_published_row_spelled_two_ways_is_one_row() -> None:
    c, n = make_key(), make_key()
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1)
    keys = [TrustKeyInput(key_id=c.kid, public_key=c.public_key)]
    filed = as_published([succ])
    other = dict(filed[n.kid][0])
    other["id"] = other["id"].upper()
    other["createdAt"] = other["createdAt"].replace("Z", "+00:00")
    filed[n.kid].append(other)
    # Read twice, the second copy would be a second admission and cut n's edge back to c.
    assert anchored_kids(walk(keys, key_statements_from_export(filed), [n.digest])) == sorted([c.kid, n.kid])


def test_a_listed_activation_no_admission_this_walk_could_verify_signs_is_window_drift() -> None:
    c, n = make_key(), make_key()
    # Published under n without its endorser c: the walk cannot verify it, so
    # n (the pin) has no signed lower edge, wider than the listed one.
    succ = statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1)
    trust = walk([row(n, T1)], _published([succ]), [n.digest])
    assert anchored_kids(trust) == [n.kid]
    assert trust.by_digest[n.digest].activated_at is None
    assert ("CHAIN_KEY_WINDOW_DRIFT", None) in codes(trust)
    # Listed with no activation, there is nothing to drift from.
    bare = TrustKeyInput(key_id=n.kid, public_key=n.public_key, algorithm=n.alg)
    assert ("CHAIN_KEY_WINDOW_DRIFT", None) not in codes(walk([bare], _published([succ]), [n.digest]))


def test_a_key_listed_retired_before_the_distrust_cutoff_the_walk_ends_it_at_is_window_drift() -> None:
    c = make_key()
    g = statement("genesis", c, signers=[c], activated_at=T0, created_at=T0)
    cutoff = [DistrustedKey(c.digest, T2)]

    # As a key document lists it: a dump's row would also be the unbounded
    # distrusted key's own finding.
    def listed(*window: str) -> TrustKeyInput:
        return replace(row(c, *window), source=None)

    early = walk([listed(T0, T1)], [g], [c.digest], cutoff)
    assert early.by_digest[c.digest].distrust_cutoff == T2
    assert codes(early) == [("CHAIN_KEY_WINDOW_DRIFT", None)]
    # Listed active, or retired at or after the cutoff, is no drift: the cutoff is no retirement.
    assert codes(walk([listed(T0)], [g], [c.digest], cutoff)) == []
    assert codes(walk([listed(T0, T3)], [g], [c.digest], cutoff)) == []


# --- distrusted keys over a key document (no write order) ---


def test_a_leaked_key_cannot_date_a_document_statement_before_its_cutoff() -> None:
    d, x = make_key(), make_key()
    g = statement("genesis", d, signers=[d], activated_at=T0, created_at=T0)
    backdated = statement("succession", x, endorser=d, signers=[d, x], activated_at=T1, created_at=T3)
    cutoff = [DistrustedKey(d.digest, T2)]
    assert x.digest not in walk([], [g, backdated], [d.digest], cutoff).trusted
    assert x.digest not in walk([], as_document([g, backdated]), [d.digest], cutoff).trusted


def test_a_routinely_closed_key_distrusted_from_its_closure_cannot_admit_a_key_by_signing_an_earlier_instant() -> None:
    c, n, x = make_key(), make_key(), make_key()
    statements = [
        statement("genesis", c, signers=[c], activated_at=T0, created_at=T0),
        statement("succession", n, endorser=c, signers=[c, n], activated_at=T1, created_at=T1),
        statement("closure", c, endorser=n, signers=[n], retired_at=T2, created_at=T2),
        statement("succession", x, endorser=c, signers=[c, x], activated_at="2026-09-02T12:00:00.000000Z", created_at=T3),
    ]
    distrust = [DistrustedKey(c.digest, None)]
    assert x.digest not in walk([], statements, [n.digest], distrust).trusted
    assert x.digest not in walk([], as_document(statements), [n.digest], distrust).trusted


# --- parsing ---


def test_trust_anchors_take_sha256_hex_entries_and_refuse_anything_else_by_name() -> None:
    d = "a" * 64
    assert parse_trust_anchors([f" sha256:{d} ", f"SHA256:{'B' * 64}"]) == [d, "b" * 64]
    assert parse_trust_anchors(f" sha256:{d} , sha256:{d}") == [d]
    assert parse_trust_anchors("") == []
    with pytest.raises(TypeError, match="sha256:abc"):
        parse_trust_anchors("sha256:abc")
    with pytest.raises(TypeError):
        parse_trust_anchors(["a" * 16])


def test_compute_key_trust_refuses_an_empty_anchor_set() -> None:
    with pytest.raises(TypeError, match="at least one trust anchor"):
        compute_key_trust(keys=[], statements=[], trust_anchors=[])


def test_distrusted_keys_parse_with_an_optional_instant_normalized_to_utc_microseconds() -> None:
    d = "a" * 64
    parsed = parse_distrusted_keys(
        f" sha256:{d} , SHA256:{'B' * 64}@2026-09-01T02:00:00.5+02:00, sha256:{'c' * 64}@2026-09-01T00:00:00.123456Z"
    )
    assert parsed == [
        DistrustedKey(d, None),
        DistrustedKey("b" * 64, "2026-09-01T00:00:00.500000Z"),
        DistrustedKey("c" * 64, "2026-09-01T00:00:00.123456Z"),
    ]
    assert parse_distrusted_keys("") == []
    with pytest.raises(TypeError, match="sha256:abc"):
        parse_distrusted_keys("sha256:abc")
    with pytest.raises(TypeError, match="@yesterday"):
        parse_distrusted_keys(f"sha256:{d}@yesterday")
    with pytest.raises(TypeError):
        parse_distrusted_keys(f"sha256:{d}@2026-13-45T00:00:00Z")
    with pytest.raises(TypeError, match="2026-02-30"):
        parse_distrusted_keys(f"sha256:{d}@2026-02-30T00:00:00Z")
    with pytest.raises(TypeError, match="twice"):
        parse_distrusted_keys(f"sha256:{d},sha256:{d}@2026-09-01T00:00:00Z")
    with pytest.raises(TypeError):
        parse_distrusted_keys(f"sha256:{d}@2026-02-28T24:00:00Z")


# --- the trust walk on random registries ---
#
# Random registries, ported from the engine: an honest history (a genesis,
# rotations, routine retirements from another active key, and sometimes a key
# anchored only by a pin) interleaved with what an attacker can store:
# statements under keys the runtime role generates, copies of rows, and, once
# one honest key leaks, statements under that key, stored any time after every
# key they name was readable, before the first honest row included. The leaked
# key is then force-retired from the current honest key.

_BASE = int(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1000)


def _iso(t: int) -> str:
    """``new Date(t).toISOString()``."""
    dt = datetime.fromtimestamp(t / 1000, tz=UTC)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{t % 1000:03d}Z"


def _at(t: int) -> str:
    return f"{_iso(t)[:23]}000Z"


def _prng(seed: int) -> Any:
    """mulberry32, as the TypeScript suite seeds it."""
    state = [seed & 0xFFFFFFFF]

    def imul(a: int, b: int) -> int:
        return (a * b) & 0xFFFFFFFF

    def nxt() -> float:
        state[0] = (state[0] + 0x6D2B79F5) & 0xFFFFFFFF
        t = state[0]
        t = imul(t ^ (t >> 15), t | 1)
        t ^= (t + imul(t ^ (t >> 7), t | 61)) & 0xFFFFFFFF
        return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296

    return nxt


def _sim_sign(
    typ: str,
    subject: TestKey,
    signers: list[TestKey],
    stored_at: int,
    *,
    endorser: TestKey | None = None,
    activated_at: int | None = None,
    retired_at: int | None = None,
    forced: bool | None = None,
    attacker: bool = False,
) -> Stored:
    payload: dict[str, Any] = {
        "typ": typ,
        "iss": "https://ledger.example",
        "subject": {
            "kid": subject.kid,
            "spkiSha256": subject.digest,
            "alg": subject.alg,
            "spki": subject.public_key,
            "activatedAt": _at(activated_at if activated_at is not None else stored_at),
            **({"retiredAt": _at(retired_at)} if retired_at is not None else {}),
        },
        "iat": stored_at // 1000 + 1,
    }
    if endorser is not None:
        payload["endorser"] = {"kid": endorser.kid, "spkiSha256": endorser.digest}
    if typ == "closure":
        payload["forced"] = bool(forced)
    data = encode_payload(payload)
    return Stored(
        id=next_id(),
        kind=typ,
        subject_key_id=subject.kid,
        endorser_key_id=endorser.kid if endorser else None,
        endorser_column=True,
        cose=[sign_statement(data, k) for k in signers],
        created_at=_iso(stored_at),
        payload=payload,
        attacker=attacker,
    )


def _in_write_order(statements: list[Stored]) -> list[Stored]:
    return sorted(statements, key=lambda s: (_ms(s.created_at or ""), s.id or ""))


def _ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso).timestamp() * 1000)


def _sim_walk_published(statements: list[Stored], anchors: set[str], keys: list[TestKey]) -> KeyTrust:
    """The same walk over the statements as a key surface publishes them,
    filed under their subject key, newest first."""
    return walk(
        [TrustKeyInput(key_id=k.kid, public_key=k.public_key, algorithm=k.alg) for k in keys],
        key_statements_from_export(as_published(list(reversed(statements)))),
        list(anchors),
    )


def _sim_walk(
    statements: list[Stored],
    anchors: set[str],
    keys: list[TestKey],
    distrusted: list[tuple[TestKey, str | None]] | None = None,
) -> KeyTrust:
    return walk(
        [TrustKeyInput(key_id=k.kid, public_key=k.public_key, algorithm=k.alg) for k in keys],
        list(_in_write_order(statements)),
        list(anchors),
        [DistrustedKey(k.digest, cutoff) for k, cutoff in (distrusted or [])],
    )


def _reference(statements: list[Stored], anchors: set[str]) -> tuple[set[str], dict[str, tuple[str | None, str | None]]]:
    """The model, restated from its definition over statements whose signatures all verify."""
    # A statement repeating an earlier one's signed payload says nothing new.
    seen: set[bytes] = set()
    order: list[Stored] = []
    for st in _in_write_order(statements):
        payload = encode_payload(st.payload)
        if payload in seen:
            continue
        seen.add(payload)
        order.append(st)

    def subject_of(s: Stored) -> str:
        return s.payload["subject"]["spkiSha256"]

    def signer_of(s: Stored) -> str | None:
        e = s.payload.get("endorser")
        return e["spkiSha256"] if e else None

    def admissions(k: str) -> list[Stored]:
        return [s for s in order if s.kind in ("genesis", "succession") and subject_of(s) == k]

    edges: list[tuple[str, str, int, bool]] = []
    for i, s in enumerate(order):
        e = signer_of(s)
        k = subject_of(s)
        if e is not None and s.kind == "succession":
            adm = admissions(k)
            edges.append((e, k, i, True))
            edges.append((k, e, i, len(adm) == 1 and adm[0] is s))

    def reach_from(es: list[tuple[str, str, int, bool]]) -> set[str]:
        t = set(anchors)
        n = -1
        while n != len(t):
            n = len(t)
            for frm, to, _i, _c in es:
                if frm in t:
                    t.add(to)
        return t

    pass1 = reach_from(edges)
    closures = [(s, i) for i, s in enumerate(order) if s.kind == "closure" and signer_of(s) in pass1]

    def closures_of(k: str) -> list[tuple[Stored, int]]:
        return [(s, i) for s, i in closures if subject_of(s) == k]

    def live(e: tuple[str, str, int, bool]) -> bool:
        return e[3] and not any(s.payload.get("forced") is True or i < e[2] for s, i in closures_of(e[0]))

    trusted = reach_from([e for e in edges if live(e)])
    windows: dict[str, tuple[str | None, str | None]] = {}
    for d in trusted:
        ends = sorted(s.payload["subject"]["retiredAt"] for s, _i in closures_of(d))
        starts = sorted((s.payload["subject"]["activatedAt"] for s in admissions(d)), reverse=True)
        windows[d] = (starts[0] if starts else None, ends[0] if ends else None)
    return trusted, windows


class _Sim:
    def __init__(self, seed: int) -> None:
        r = _prng(seed)

        def pick(xs: list[Any]) -> Any:
            return xs[int(r() * len(xs))]

        now = _BASE

        def tick() -> None:
            nonlocal now
            now += 1000 + int(r() * 3) * 1000

        statements: list[Stored] = []
        attacker_keys = [make_key(name="A0"), make_key(name="A1"), make_key(name="A2")]
        pre_start = now - 100_000
        now += 1000
        g = make_key(name="G")
        honest = [g]
        statements.append(_sim_sign("genesis", g, [g], now, activated_at=now))
        anchor_only = make_key(name="P") if r() < 0.3 else None
        active = [g]
        current = g
        leaked: TestKey | None = None

        def known_at(k: TestKey) -> int:
            if k in attacker_keys or k is g or k is anchor_only:
                return pre_start + 1
            admitted = next((x for x in statements if not x.attacker and x.payload["subject"]["spkiSha256"] == k.digest), None)
            return _ms(admitted.created_at or "") if admitted is not None else now

        steps = 6 + int(r() * 10)
        for _step in range(steps):
            tick()
            roll = r()
            if roll < 0.25:
                nxt = make_key(name=f"H{len(honest)}")
                honest.append(nxt)
                statements.append(_sim_sign("succession", nxt, [current, nxt], now, endorser=current, activated_at=now))
                active.append(nxt)
                current = nxt
            elif roll < 0.4:
                candidates = [k for k in active if k is not current]
                if not candidates:
                    continue
                leaving = pick(candidates)
                by = pick([k for k in active if k is not leaving])
                statements.append(_sim_sign("closure", leaving, [by], now, endorser=by, retired_at=now))
                active.remove(leaving)
            elif roll < 0.5 and leaked is None:
                leaked = pick([*honest, *([anchor_only] if anchor_only else [])])
            elif r() < 0.15 and statements:
                src = pick(statements)
                statements.append(replace(src, id=next_id(), created_at=_iso(now), attacker=True))
            else:
                held = [*attacker_keys, *([leaked] if leaked else [])]
                typ = pick(["succession", "closure", "genesis", "succession"])
                subject = (
                    pick(held)
                    if typ == "genesis"
                    else pick([*honest, *([anchor_only] if anchor_only else []), *attacker_keys])
                )
                endorser = pick(held)
                if (typ != "genesis" and endorser is subject) or (typ == "succession" and subject not in held):
                    continue
                window_start = pick([pre_start, now - 3000, now])
                window_end = pick([pre_start + 1, now - 1000, now])
                frm = max([pre_start + 1, *(known_at(k) for k in (subject, endorser) if k is not leaked)])
                stored_at = now if r() < 0.5 else frm + int(r() * max(1, now - frm))
                signers = [subject] if typ == "genesis" else [endorser, subject] if typ == "succession" else [endorser]
                statements.append(
                    _sim_sign(
                        typ,
                        subject,
                        signers,
                        stored_at,
                        endorser=endorser if typ != "genesis" else None,
                        activated_at=window_start,
                        retired_at=max(window_start, window_end) if typ == "closure" else None,
                        forced=r() < 0.5,
                        attacker=True,
                    )
                )
        if leaked is not None:
            tick()
            if current is leaked:
                nxt = make_key(name=f"H{len(honest)}")
                honest.append(nxt)
                statements.append(_sim_sign("succession", nxt, [leaked, nxt], now, endorser=leaked, activated_at=now))
                current = nxt
                tick()
            statements.append(_sim_sign("closure", leaked, [current], now, endorser=current, retired_at=now, forced=True))
        self.seed = seed
        self.statements = statements
        self.honest = honest
        self.anchor_only = anchor_only
        self.leaked = leaked
        self.attacker_keys = attacker_keys

    def anchors_for(self, pin: TestKey) -> set[str]:
        return {pin.digest, *([self.anchor_only.digest] if self.anchor_only else [])}

    def keys_of(self, attacker: bool) -> list[TestKey]:
        return [*self.honest, *([self.anchor_only] if self.anchor_only else []), *(self.attacker_keys if attacker else [])]


# KEY_TRUST_SEEDS=<first>:<count> runs a wider sweep locally.
_FIRST, _COUNT = (int(p) for p in (os.environ.get("KEY_TRUST_SEEDS") or "1:150").split(":"))


@pytest.fixture(scope="module")
def registries() -> list[_Sim]:
    return [_Sim(_FIRST + i) for i in range(_COUNT)]


def test_random_registries_compute_what_the_model_defines_from_every_honest_pin(registries: list[_Sim]) -> None:
    failures: list[str] = []
    for sim in registries:
        for pin in sim.honest:
            got = _sim_walk(sim.statements, sim.anchors_for(pin), sim.keys_of(True))
            if got.statements.valid != got.statements.total:
                failures.append(f"seed {sim.seed}: a statement does not verify, which the model does not cover")
            trusted, windows = _reference(sim.statements, sim.anchors_for(pin))
            tag = f"seed {sim.seed}, pinned on {pin.name}"
            if sorted(got.trusted) != sorted(trusted):
                failures.append(f"{tag}: trusted set differs")
            for d, (start, end) in windows.items():
                e = got.by_digest.get(d)
                if e is None or e.activated_at != start or e.retired_at != end:
                    failures.append(f"{tag}: window of {d[:8]} differs from the model's {start}..{end}")
    assert failures == []


def _widenings(tag: str, attacked: KeyTrust, base: KeyTrust) -> list[str]:
    out: list[str] = []
    for d in attacked.trusted:
        if d not in base.trusted:
            out.append(f"{tag}: {d[:8]} is trusted only because of the attacker's rows")
            continue
        a = attacked.by_digest[d]
        b = base.by_digest[d]
        if b.activated_at is not None and (a.activated_at is None or a.activated_at < b.activated_at):
            out.append(f"{tag}: {d[:8]} activates at {a.activated_at}, before {b.activated_at}")
        a_ends = a.distrust_cutoff or a.retired_at
        b_ends = b.distrust_cutoff or b.retired_at
        if b_ends is not None and (a_ends is None or a_ends > b_ends):
            out.append(f"{tag}: {d[:8]} retires at {a_ends}, past {b_ends}")
    return out


def test_random_registries_after_a_forced_closure_nothing_the_attacker_stored_widens_trust(registries: list[_Sim]) -> None:
    failures: list[str] = []
    for sim in registries:
        honest_only = [s for s in sim.statements if not s.attacker]
        for pin in sim.honest:
            tag = f"seed {sim.seed}, pinned on {pin.name}, leaked {sim.leaked.name if sim.leaked else 'none'}"
            failures += _widenings(
                tag,
                _sim_walk(sim.statements, sim.anchors_for(pin), sim.keys_of(True)),
                _sim_walk(honest_only, sim.anchors_for(pin), sim.keys_of(False)),
            )
    assert failures == []


def test_random_registries_with_the_leaked_key_distrusted_nothing_the_attacker_stored_widens_trust(
    registries: list[_Sim],
) -> None:
    failures: list[str] = []
    covered = 0
    for sim in registries:
        leaked = sim.leaked
        if leaked is None:
            continue
        by_leaked = [
            s
            for s in sim.statements
            if s.attacker and leaked.digest in ((s.payload.get("endorser") or {}).get("spkiSha256"), s.payload["subject"]["spkiSha256"])
        ]
        if not by_leaked:
            continue
        leaked_from = min(_ms(s.created_at or "") for s in by_leaked)
        covered += 1
        unretired = [
            s
            for s in sim.statements
            if not (s.kind == "closure" and not s.attacker and s.payload.get("forced") is True and s.subject_key_id == leaked.kid)
        ]
        for statements, cutoff in ((sim.statements, None), (unretired, _at(leaked_from))):
            honest_only = [s for s in statements if not s.attacker]
            for pin in sim.honest:
                if pin is leaked:
                    continue
                tag = f"seed {sim.seed}, pinned on {pin.name}, {leaked.name} distrusted{'' if cutoff is None else f' from {cutoff}, never retired'}"
                distrusted = [(leaked, cutoff)]
                failures += _widenings(
                    tag,
                    _sim_walk(statements, sim.anchors_for(pin), sim.keys_of(True), distrusted),
                    _sim_walk(honest_only, sim.anchors_for(pin), sim.keys_of(False), distrusted),
                )
    assert covered > 0
    assert failures == []


def test_random_registries_a_document_walk_over_the_honest_history_matches_the_dump_walk(registries: list[_Sim]) -> None:
    failures: list[str] = []
    for sim in registries:
        honest_only = _in_write_order([s for s in sim.statements if not s.attacker])
        for pin in sim.honest:
            dump = _sim_walk(honest_only, sim.anchors_for(pin), sim.keys_of(False))
            doc = walk(
                [TrustKeyInput(key_id=k.kid, public_key=k.public_key, algorithm=k.alg) for k in sim.keys_of(False)],
                as_document(list(reversed(honest_only))),
                list(sim.anchors_for(pin)),
            )
            tag = f"seed {sim.seed}, pinned on {pin.name}"
            published = _sim_walk_published(honest_only, sim.anchors_for(pin), sim.keys_of(False))
            if sorted(published.trusted) != sorted(dump.trusted) or any(
                published.by_digest.get(d) != dump.by_digest.get(d) for d in dump.trusted
            ):
                failures.append(f"{tag}: the published document's walk differs")
            if sorted(doc.trusted) != sorted(dump.trusted):
                failures.append(f"{tag}: trusted set differs")
            failures.extend(
                f"{tag}: window of {d[:8]} differs"
                for d in dump.trusted
                if doc.by_digest.get(d) != dump.by_digest.get(d)
            )
    assert failures == []


def test_a_write_time_is_strict_rfc3339_and_reads_every_offset_and_case_it_allows() -> None:
    from agledger.verify.key_statements import instant_ms, rfc3339_ms

    z = rfc3339_ms("2026-09-01T00:00:00Z")
    assert z is not None
    for same in ("2026-09-01T00:00:00.000Z", "2026-09-01t00:00:00z", "2026-09-01T02:00:00+02:00", "2026-08-31T23:30:00-00:30"):
        assert rfc3339_ms(same) == z, same
    assert rfc3339_ms("2024-02-29T00:00:00Z") is not None
    for bad in ("2026-09-01T00:00:00", "2026-09-01 00:00:00Z", "1", "2026-02-30T00:00:00.000000Z", "2025-02-29T00:00:00Z", "2026-09-01T00:60:00Z", ""):
        assert rfc3339_ms(bad) is None, bad
    # Every instant is strict, a key window included.
    assert instant_ms("2026-09-01T00:00:00") is None
    assert instant_ms("2026-09-01T00:00:00Z") == z
