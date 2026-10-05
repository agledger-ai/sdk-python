"""A distrusted key's writes on a dump, as the engine's scan accounts for them,
mirroring verify-core's distrust-accounting tests: what it signed outside its
trust before a key the walk trusts retired it is listed as
CHAIN_SIGNED_BY_DISTRUSTED_KEY and fails nothing; what it signed after is a
failure. Also the walk's own accounting of its statements, a copied
key-statement row as a no-op, and the dated pin-and-distrust pair."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar

import cbor2

from agledger.verify import (
    DistrustedKey,
    KeyTrust,
    TrustKeyInput,
    chain_of_scope,
    compute_key_trust,
    key_statement_from_dump_row,
    load_dump,
    spki_sha256,
    trust_key_from_dump_row,
    verify_dump,
)
from agledger.verify.key_statements import KeyStatementInput
from agledger.verify.verify_dump import verify_vault_chains
from agledger.verify.verify_export import KeyCache, RegisteredKey, apply_key_trust

from .key_statement_helpers import (
    EXPORT_DIR,
    T0,
    T1,
    T2,
    T3,
    Stored,
    TestKey,
    make_key,
    raw_sign,
    row,
    statement,
)

_CORPUS = Path(__file__).resolve().parents[1] / "testdata" / "conformance"


def _at(m: int) -> str:
    return f"2026-09-02T00:{m:02d}:00.000000Z"


def _written(m: int, s: int = 30) -> str:
    return f"2026-09-02T00:{m:02d}:{s:02d}.000Z"


def _walk(
    keys: list[TrustKeyInput],
    statements: list[Any],
    anchors: list[TestKey],
    distrusted: list[DistrustedKey] | None = None,
) -> KeyTrust:
    return compute_key_trust(
        keys=keys,
        statements=statements,
        trust_anchors=[f"sha256:{k.digest}" for k in anchors],
        distrusted_keys=distrusted,
    )


def _chain(signers: list[tuple[TestKey, str, bool]]) -> list[dict[str, Any]]:
    """valid.json's entries as dump rows, each signed under the key given for it
    and written at the time given (the bool corrupts its signature)."""
    exp: dict[str, Any] = json.loads((EXPORT_DIR / "valid.json").read_text())
    prev: bytes | None = None
    rows: list[dict[str, Any]] = []
    for e, (key, created_at, corrupt) in zip(exp["entries"], signers, strict=False):
        tagged: Any = cbor2.loads(base64.b64decode(e["integrity"]["coseSign1"]))
        protected, _unprotected, payload, _sig = tagged.value
        header: dict[int, Any] = cbor2.loads(protected)
        header[4] = bytes.fromhex(key.kid)
        header[-65537] = {**header[-65537], 2: prev}
        new_protected = cbor2.dumps(header, canonical=True)
        signature = bytearray(raw_sign(key, cbor2.dumps(["Signature1", new_protected, b"", payload], canonical=True)))
        if corrupt:
            signature[0] ^= 0xFF
        env = cbor2.dumps(cbor2.CBORTag(18, [new_protected, {}, payload, bytes(signature)]), canonical=True)
        digest = hashlib.sha256(env).digest()
        rows.append(
            {
                "id": f"row-{len(rows)}",
                "record_id": e["recordId"],
                "chain_key": e["recordId"],
                "entry_type": e["entryType"],
                "payload": e["payload"],
                "payload_hash": digest.hex(),
                "previous_hash": None if prev is None else prev.hex(),
                "chain_position": e["chainPosition"],
                "cose_sign1": base64.b64encode(env).decode(),
                "signing_key_id": key.kid,
                "actor_key_id": e["actorId"],
                "actor_role": e["actorRole"],
                "actor_owner_id": e["actorOwnerId"],
                "actor_oidc_iss": e["actorOidcIss"],
                "actor_oidc_sub": e["actorOidcSub"],
                "actor_oidc_synthesized": e["actorOidcSynthesized"],
                "created_at": created_at,
            }
        )
        prev = digest
    return rows


def _registry(keys: list[TestKey], trust: KeyTrust) -> KeyCache:
    return apply_key_trust(
        KeyCache({k.kid: RegisteredKey(k.public_key, "embedded", activated_at=T0) for k in keys}, signing_since=None),
        trust,
    )


class TestADumpEntrySignedByADistrustedKey:
    """P leaked; the attacker staged S from it and force-retired P from S. The
    operator's N runs under a fresh genesis with P pinned, retires P with
    force, distrusts S from its closure, and retires S with force at 00:05."""

    p, s, n = make_key(), make_key(), make_key()
    base: ClassVar[list[Stored]] = [
        statement("genesis", p, signers=[p], activated_at=T0, created_at=T0),
        statement("succession", s, endorser=p, signers=[p, s], activated_at=_at(1), created_at=_at(1)),
        statement("closure", p, endorser=s, signers=[s], retired_at=_at(2), forced=True, created_at=_at(2)),
        statement("genesis", n, signers=[n], activated_at=_at(3), created_at=_at(3)),
        statement("closure", p, endorser=n, signers=[n], retired_at=_at(2), forced=True, created_at=_at(4)),
    ]
    retire_s = statement("closure", s, endorser=n, signers=[n], retired_at=_at(5), forced=True, created_at=_at(5))
    distrusted: ClassVar[list[DistrustedKey]] = [DistrustedKey(s.digest, _at(2))]
    rows: ClassVar[list[TrustKeyInput]] = [row(p, T0, _at(2)), row(s, _at(1), _at(5)), row(n, _at(3))]

    def test_before_a_trusted_key_retired_it_is_accounted_for_and_listed_and_the_chain_passes(self) -> None:
        trust = _walk(self.rows, [*self.base, self.retire_s], [self.p, self.n], self.distrusted)
        assert trust.findings == []
        reg = _registry([self.p, self.s, self.n], trust)
        marked = reg.entry(self.s.kid)
        assert marked is not None and marked.trust == "unanchored"
        assert marked.distrust_span is not None
        assert (marked.distrust_span.cutoff, marked.distrust_span.retired_at) == (_at(2), _at(5))
        chain = _chain([(self.s, _written(2), False), (self.s, _written(4), False), (self.n, _written(6), False)])
        report = verify_vault_chains(chain, [], [], reg)
        assert report.failures == []
        assert report.signed_entries == 1
        assert [(a.code, a.chain, a.record_id, a.position, a.key_id) for a in report.accounted] == [
            ("CHAIN_SIGNED_BY_DISTRUSTED_KEY", "record", chain[0]["record_id"], 1, self.s.kid),
            ("CHAIN_SIGNED_BY_DISTRUSTED_KEY", "record", chain[0]["record_id"], 2, self.s.kid),
        ]
        assert report.to_json()["accountedCount"] == 2

    def test_after_that_retirement_or_with_a_signature_that_does_not_verify_fails_as_before(self) -> None:
        reg = _registry([self.p, self.s, self.n], _walk(self.rows, [*self.base, self.retire_s], [self.p, self.n], self.distrusted))
        late = verify_vault_chains(_chain([(self.s, _written(5, 1), False)]), [], [], reg)
        assert [f.code for f in late.failures] == ["CHAIN_SIGNING_KEY_UNANCHORED"]
        assert late.accounted == []
        forged = verify_vault_chains(_chain([(self.s, _written(2), True)]), [], [], reg)
        assert [f.code for f in forged.failures] == ["CHAIN_SIGNING_KEY_UNANCHORED"]

    def test_under_a_distrusted_key_no_trusted_key_has_retired_fails_as_before_and_the_key_is_a_finding(self) -> None:
        trust = _walk([self.rows[0], row(self.s, _at(1)), self.rows[2]], self.base, [self.p, self.n], self.distrusted)
        assert ("KEY_CLOSURE_INVALID", self.s.kid) in [(f.code, f.key_id) for f in trust.findings]
        report = verify_vault_chains(_chain([(self.s, _written(2), False)]), [], [], _registry([self.p, self.s, self.n], trust))
        assert [f.code for f in report.failures] == ["CHAIN_SIGNING_KEY_UNANCHORED"]

    def test_is_never_accounted_for_on_a_key_document(self) -> None:
        doc = [replace(st, source="document") for st in [*self.base, self.retire_s]]
        listed = [TrustKeyInput(key_id=k.kid, public_key=k.public_key) for k in (self.p, self.s, self.n)]
        trust = _walk(listed, doc, [self.p, self.n], self.distrusted)
        assert trust.accounted == []
        reg = _registry([self.p, self.s, self.n], trust)
        marked = reg.entry(self.s.kid)
        assert marked is not None and marked.distrust_span is None
        report = verify_vault_chains(_chain([(self.s, _written(2), False)]), [], [], reg)
        assert [f.code for f in report.failures] == ["CHAIN_SIGNING_KEY_UNANCHORED"]

    def test_its_statements_are_accounted_for_and_one_signed_after_the_retirement_is_reported(self) -> None:
        by_s = self.base[2]
        retired = _walk(self.rows, [*self.base, self.retire_s], [self.p, self.n], self.distrusted)
        assert [(a.key_id, a.statement_id) for a in retired.accounted] == [(self.p.kid, by_s.id)]
        assert "the distrust entry accounts for it" in retired.accounted[0].detail
        later = statement("closure", self.n, endorser=self.s, signers=[self.s], retired_at=_at(3), forced=True, created_at=_at(6))
        again = _walk(self.rows, [*self.base, self.retire_s, later], [self.p, self.n], self.distrusted)
        assert [f.statement_id for f in again.findings] == [later.id]
        assert "still in use by someone with write access" in again.findings[0].detail
        assert again.by_digest[self.n.digest].retired_at is None
        ahead = statement(
            "closure", self.s, endorser=self.n, signers=[self.n], retired_at="2099-01-01T00:00:00.000000Z", forced=True, created_at=_at(5)
        )
        span = _walk(self.rows, [*self.base, ahead], [self.p, self.n], self.distrusted).distrust_spans[self.s.digest]
        assert (span.cutoff, span.retired_at) == (_at(2), _at(5))


def test_a_pinned_key_distrusted_from_an_instant_verifies_before_it_is_accounted_for_until_its_retirement_and_fails_after() -> None:
    c, n = make_key(), make_key()
    statements = [
        statement("genesis", c, signers=[c], activated_at=T0, created_at=T0),
        statement("genesis", n, signers=[n], activated_at=_at(1), created_at=_at(1)),
        statement("closure", c, endorser=n, signers=[n], retired_at=_at(5), forced=True, created_at=_at(5)),
    ]
    trust = _walk([row(c, T0, _at(5)), row(n, _at(1))], statements, [c, n], [DistrustedKey(c.digest, _at(2))])
    assert trust.findings == []
    reg = _registry([c, n], trust)
    marked = reg.entry(c.kid)
    assert marked is not None and (marked.trust, marked.distrust_cutoff) == ("anchored", _at(2))
    report = verify_vault_chains(_chain([(c, _written(1), False), (c, _written(3), False), (c, _written(5, 1), False)]), [], [], reg)
    assert [a.position for a in report.accounted] == [2]
    assert [(f.code, f.position) for f in report.failures] == [("CHAIN_KEY_EXPIRED", 3)]
    forged = verify_vault_chains(_chain([(c, _written(1), False), (c, _written(3), True)]), [], [], reg)
    assert [(f.code, f.position) for f in forged.failures] == [("CHAIN_SIGNATURE_INVALID", 2)]
    assert forged.accounted == []


def test_pinned_and_leaked_its_closure_of_the_key_that_retired_it_counts_until_a_dated_entry_beside_the_pin_voids_it() -> None:
    d0, d1 = make_key(), make_key()
    d1_active = "2026-09-03T00:00:00.000000Z"
    statements = [
        statement("genesis", d0, signers=[d0], activated_at=T0, created_at=T0),
        statement("genesis", d1, signers=[d1], activated_at=d1_active, created_at=d1_active),
        statement("closure", d0, endorser=d1, signers=[d1], retired_at=T1, forced=True, created_at="2026-09-03T00:00:01.000000Z"),
    ]
    backdated = statement(
        "closure", d1, endorser=d0, signers=[d0], retired_at="2026-09-03T00:00:00.500000Z", forced=True, created_at=T3
    )
    rows = [row(d0, T0, T1), row(d1, d1_active)]
    attacked = _walk(rows, [*statements, backdated], [d0, d1])
    assert attacked.by_digest[d1.digest].retired_at == "2026-09-03T00:00:00.500000Z"
    finding = next(f for f in attacked.findings if f.statement_id == backdated.id)
    assert "after its own retirement, and still counts" in finding.detail
    assert f"distrustedKeys sha256:{d0.digest}@<instant>" in finding.detail
    assert f"if nothing earlier is known, {T1}, its retirement" in finding.detail
    assert "Keep a trustAnchors pin" in finding.detail
    healed = _walk(rows, [*statements, backdated], [d0, d1], [DistrustedKey(d0.digest, T1)])
    assert healed.by_digest[d1.digest].trusted and healed.by_digest[d1.digest].retired_at is None
    assert next(f for f in healed.findings if f.statement_id == backdated.id).detail.endswith(
        "still in use by someone with write access to the Server's database."
    )
    assert healed.accounted == []


def test_a_retirement_dated_ahead_of_its_write_time_is_a_finding_and_the_instant_it_suggests_is_capped() -> None:
    d0, d1 = make_key(), make_key()
    far = "2099-01-01T00:00:00.000000Z"
    ahead = statement("closure", d0, endorser=d1, signers=[d1], retired_at=far, forced=True, created_at=T2)
    after = statement("closure", d1, endorser=d0, signers=[d0], retired_at=T1, forced=True, created_at=T3)
    gens = [
        statement("genesis", d0, signers=[d0], activated_at=T0, created_at=T0),
        statement("genesis", d1, signers=[d1], activated_at=T1, created_at=T1),
    ]
    trust = _walk([row(d0, T0), row(d1, T1)], [*gens, ahead, after], [d0, d1])
    assert f"after {T2[:23]}Z when it was stored" in next(f for f in trust.findings if f.statement_id == ahead.id).detail
    hint = next(f for f in trust.findings if f.statement_id == after.id).detail
    assert f"if nothing earlier is known, {T2}, its retirement" in hint
    assert far not in hint
    same_ms = statement("closure", d0, endorser=d1, signers=[d1], retired_at="2026-09-03T00:00:00.000900Z", created_at=T2)
    assert _walk([], [*gens, same_ms], [d0, d1]).findings == []


def test_chain_of_scope_names_a_chain_as_the_engine_does() -> None:
    assert chain_of_scope("7b1c0f6e-0000-4000-8000-000000000001") == ("record", "7b1c0f6e-0000-4000-8000-000000000001", None)
    assert chain_of_scope("00000000-0000-0000-0000-000000000000") == ("admin", None, None)
    assert chain_of_scope("schema:4a0e7f00-0000-4000-8000-000000000002") == ("schema", None, "4a0e7f00-0000-4000-8000-000000000002")
    assert chain_of_scope("schema:__platform__") == ("schema", None, None)


def _current_pin(dump_dir: Path) -> str:
    d = load_dump(str(dump_dir))
    admitted = {s["subject_key_id"] for s in d.key_statements if s["kind"] != "closure"}
    key = max((k for k in d.signing_keys if k["key_id"] in admitted), key=lambda k: k["activated_at"])
    return f"sha256:{spki_sha256(key['public_key'])}"


def test_every_vault_key_statements_row_copied_under_a_new_id_and_write_time_is_a_no_op_as_the_engine_reads_it() -> None:
    # What anything with the runtime role can do to the append-only table:
    # INSERT ... SELECT subject_key_id, endorser_key_id, kind, statement.
    for name in ("valid", "valid-es256", "valid-identity", "valid-unsigned-history-then-signed", "valid-rotation-boundary", "valid-key-succession"):
        d = load_dump(str(_CORPUS / "dump" / name))
        pin = _current_pin(_CORPUS / "dump" / name)
        assert verify_dump(copy.deepcopy(d), trust_anchors=[pin]).verdict == "trusted", name
        d.key_statements = [
            *d.key_statements,
            *({**r, "id": f"ffffffff-0000-4000-8000-{i:012d}", "created_at": "2099-01-01T00:00:00.000Z"} for i, r in enumerate(d.key_statements)),
        ]
        report = verify_dump(d, trust_anchors=[pin])
        assert (report.verdict, report.key_trust.findings) == ("trusted", []), name
        trust = compute_key_trust(
            keys=[trust_key_from_dump_row(k) for k in d.signing_keys],
            statements=[key_statement_from_dump_row(r) for r in d.key_statements],
            trust_anchors=[pin],
        )
        assert trust.statements.total == len(d.key_statements)


def test_a_dump_statement_input_is_a_dump_row() -> None:
    st = key_statement_from_dump_row({"id": "x", "kind": "genesis", "subject_key_id": "a", "endorser_key_id": None, "statement": [], "created_at": T0})
    assert isinstance(st, KeyStatementInput) and st.source == "dump"
    assert trust_key_from_dump_row({"key_id": "a", "public_key": "", "status": "active"}).source == "dump"


# --- narrower than the engine where its reading accounts for what should fail ---


def test_a_key_document_copy_dated_earlier_does_not_push_the_published_statement_aside() -> None:
    e, n, k = make_key(), make_key(), make_key()

    def doc(s: Stored, row_id: str, created_at: str) -> KeyStatementInput:
        return KeyStatementInput(id=row_id, kind=s.kind, subject_key_id=s.subject_key_id, source="document", cose=s.cose, created_at=created_at)

    supplied = [
        doc(statement("genesis", e, signers=[e], activated_at=T0), "supplied:1", _at(0)),
        doc(statement("genesis", n, signers=[n], activated_at=_at(1)), "supplied:2", _at(1)),
        doc(statement("closure", e, endorser=n, signers=[n], retired_at=_at(2)), "supplied:3", _at(2)),
    ]
    s_k = statement("succession", k, endorser=e, signers=[e, k], activated_at=_at(5))
    keys = [TrustKeyInput(key_id=x.kid, public_key=x.public_key) for x in (e, n, k)]
    honest = _walk(keys, [*supplied, doc(s_k, "supplied:4", _at(5))], [e, n])
    copied = _walk(keys, [doc(s_k, "copy:1", "2026-09-02T00:01:30.000000Z"), *supplied, doc(s_k, "supplied:4", _at(5))], [e, n])
    assert [f.code for f in honest.findings] == ["KEY_STATEMENT_INVALID"]
    assert copied.findings


def test_only_a_retirement_a_key_the_walk_trusts_signed_bounds_what_a_distrust_entry_accounts_for() -> None:
    f, m, m2, n = make_key(), make_key(), make_key(), make_key()
    statements = [
        statement("genesis", f, signers=[f], activated_at=T0, created_at=T0),
        statement("succession", m, endorser=f, signers=[f, m], activated_at=_at(1), created_at=_at(1)),
        statement("succession", m2, endorser=f, signers=[f, m2], activated_at=_at(1), created_at=_at(2)),
        statement("genesis", n, signers=[n], activated_at=_at(3), created_at=_at(3)),
        statement("closure", f, endorser=n, signers=[n], retired_at=_at(3), forced=True, created_at=_at(4)),
        statement("closure", m, endorser=m2, signers=[m2], retired_at=_at(50), created_at=_at(50)),
    ]
    trust = _walk(
        [row(f, T0, _at(3)), row(m, _at(1)), row(m2, _at(1)), row(n, _at(3))], statements, [f, n], [DistrustedKey(m.digest, None)]
    )
    assert trust.distrust_spans[m.digest].retired_at is None
    assert [x.code for x in trust.findings if x.statement_id is None and x.key_id == m.kid] == ["KEY_CLOSURE_INVALID"]


def test_a_later_admission_of_a_trusted_key_that_the_key_signed_is_a_finding_whichever_distrusted_key_co_signed_it() -> None:
    a, leaked, x = make_key(), make_key(), make_key()
    later = statement("succession", x, endorser=leaked, signers=[leaked, x], activated_at=_at(4), created_at=_at(4))
    trust = _walk(
        [row(a, T0), row(leaked, _at(1), _at(10)), row(x, _at(2))],
        [
            statement("genesis", a, signers=[a], activated_at=T0, created_at=T0),
            statement("succession", leaked, endorser=a, signers=[a, leaked], activated_at=_at(1), created_at=_at(1)),
            statement("succession", x, endorser=a, signers=[a, x], activated_at=_at(2), created_at=_at(2)),
            later,
            statement("closure", leaked, endorser=a, signers=[a], retired_at=_at(10), forced=True, created_at=_at(10)),
        ],
        [a],
        [DistrustedKey(leaked.digest, _at(3))],
    )
    assert trust.accounted == []
    assert "signed after it was already admitted" in next(f for f in trust.findings if f.statement_id == later.id).detail
