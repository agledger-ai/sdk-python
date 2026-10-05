"""The walk against the engine's own verdicts on the same random registries:
statements of every kind in any signer order, write times and signed instants
that tie, duplicated rows, and distrusted keys with and without a cutoff. The
verdicts in ``fixtures/key-trust-engine.json`` were recorded from the engine's
``computeKeyTrust`` by verify-core's ``scripts/record-key-trust-engine.mts``,
and verify-core holds its walk to the same file, exactly. The scenarios are regenerated
here from the seed exactly as verify-core's ``key-trust-fuzz.ts`` generates
them, so a divergence in either the generator or the walk fails this test."""

from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agledger.verify.key_statements import (
    DistrustedKey,
    KeyStatementInput,
    KeyTrust,
    TrustKeyInput,
    compute_key_trust,
    key_statements_from_verification_keys,
)

from .key_statement_helpers import TestKey, encode_payload, sign_statement

_RECORDED = json.loads((Path(__file__).parent / "fixtures" / "key-trust-engine.json").read_text())


def _prng(seed: int) -> Callable[[], float]:
    """mulberry32, as verify-core's key-trust-fuzz.ts seeds it."""
    state = [seed & 0xFFFFFFFF]

    def nxt() -> float:
        state[0] = (state[0] + 0x6D2B79F5) & 0xFFFFFFFF
        t = state[0]
        t = ((t ^ (t >> 15)) * (t | 1)) & 0xFFFFFFFF
        t ^= (t + (((t ^ (t >> 7)) * (t | 61)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296

    return nxt


def _v8_sort_with_random_comparator(items: list[int], compare: Callable[[], float]) -> list[int]:
    """``Array.prototype.sort(() => r() - 0.5)`` as V8 runs it on a short
    array: its TimSort makes one run (``CountAndMakeRun``) and extends it by
    binary insertion, calling the comparator in a fixed order, so the
    permutation is a function of the comparator's answers."""
    work = list(items)
    n = len(work)
    if n < 2:
        return work
    assert n < 64, "one run only: a longer array would merge runs"
    run = 2
    descending = compare() < 0
    for _idx in range(2, n):
        order = compare()
        if (descending and order >= 0) or (not descending and order < 0):
            break
        run += 1
    if descending:
        work[:run] = reversed(work[:run])
    for start in range(run, n):
        left, right = 0, start
        pivot = work[start]
        while left < right:
            mid = left + ((right - left) >> 1)
            if compare() < 0:
                right = mid
            else:
                left = mid + 1
        work[left + 1 : start + 1] = work[left:start]
        work[left] = pivot
    return work


def _fixed_key(i: int) -> TestKey:
    seed = hashlib.sha256(f"agledger-key-trust-fuzz-{i}".encode()).digest()
    alg = "ES256" if i % 3 == 2 else "Ed25519"
    private: Any = (
        Ed25519PrivateKey.from_private_bytes(seed)
        if alg == "Ed25519"
        else ec.derive_private_key(int.from_bytes(seed, "big"), ec.SECP256R1())
    )
    der = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    import base64

    digest = hashlib.sha256(der).hexdigest()
    return TestKey(private, base64.b64encode(der).decode(), digest, digest[:16], alg)  # type: ignore[arg-type]


POOL = [_fixed_key(i) for i in range(12)]
_INDEX_OF_KID = {k.kid: i for i, k in enumerate(POOL)}
_INDEX_OF_DIGEST = {k.digest: i for i, k in enumerate(POOL)}
_BASE = int(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1000)


def _iso(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000, tz=UTC)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{ms % 1000:03d}Z"


def _us(ms: int, sub: int) -> str:
    return f"{_iso(ms)[:23]}{sub:03d}Z"


def _to_ms(instant: str) -> str:
    return f"{instant[:23]}Z"


@dataclass
class _Scenario:
    statements: list[dict[str, Any]]
    anchors: list[int]
    distrusted: list[tuple[int, str | None]]
    rows: list[dict[str, Any]]


def _scenario(seed: int) -> _Scenario:
    r = _prng(seed)

    def pick(xs: list[Any]) -> Any:
        return xs[int(r() * len(xs))]

    keys = _v8_sort_with_random_comparator(list(range(len(POOL))), lambda: r() - 0.5)
    keys = keys[: 5 + int(r() * 5)]
    now = [_BASE]
    idn = [0]

    def next_id() -> str:
        """A uuid-shaped row id whose order is unrelated to the write order."""
        idn[0] += 1
        head = f"{int(r() * 0x100000000):x}".rjust(8, "0")
        return f"{head}-0000-4000-8000-{idn[0]:012d}"

    last_sub = [0]

    def written(ms: int) -> str:
        """A write time in millisecond ``ms``, sometimes the same microsecond as the last one."""
        if r() >= 0.25:
            last_sub[0] = int(r() * 1000)
        return _us(ms, last_sub[0])

    def t() -> str:
        ms = _BASE + int(r() * 20) * 1000
        ms += int(r() * 3)
        return _us(ms, int(r() * 1000))

    statements: list[dict[str, Any]] = []

    def add(typ: str, subject: int, endorser: int, activated_at: str, signer_choice: float) -> None:
        if typ == "genesis":
            signers = [subject]
        elif typ == "succession":
            signers = [endorser, subject] if signer_choice < 0.9 else [endorser] if r() < 0.5 else [subject, endorser]
        else:
            signers = [endorser]
        retired_at = t()
        with_retired = typ == "closure" or r() < 0.1
        forced = (r() < 0.3) if typ == "closure" else None
        s, e = POOL[subject], POOL[endorser]
        payload: dict[str, Any] = {
            "typ": typ,
            "iss": "https://x",
            "subject": {
                "kid": s.kid,
                "spkiSha256": s.digest,
                "alg": s.alg,
                "spki": s.public_key,
                "activatedAt": activated_at,
                **({"retiredAt": retired_at} if with_retired else {}),
            },
            "iat": 1,
        }
        if typ != "genesis":
            payload["endorser"] = {"kid": e.kid, "spkiSha256": e.digest}
        if forced is not None:
            payload["forced"] = forced
        data = encode_payload(payload)
        row_id = next_id()
        st = {
            "id": row_id,
            "kind": typ,
            "subject": subject,
            "endorser": endorser if typ != "genesis" else None,
            "cose": [sign_statement(data, POOL[k]) for k in signers],
            "created_ms": now[0],
            "created_us": written(now[0]),
        }
        statements.append(st)
        if r() < 0.1:
            dup_id = next_id()
            statements.append({**st, "id": dup_id, "created_ms": now[0] + 1, "created_us": written(now[0] + 1)})

    n = 3 + int(r() * 12)
    for _i in range(n):
        step = int(r() * 3) * 1000
        now[0] += step + (0 if r() < 0.2 else 1)
        typ = pick(["genesis", "succession", "succession", "closure", "closure"])
        subject = pick(keys)
        endorser = pick([k for k in keys if k != subject])
        activated_at = t()
        add(typ, subject, endorser, activated_at, r())
    first = pick(keys)
    anchors = list(dict.fromkeys([first, *([pick(keys)] if r() < 0.3 else [])]))
    # Later admissions of a key the walk is likely to trust: each dates its
    # window and cuts its edge back, and the key documents publish them.
    later = 1 + int(r() * 2) if r() < 0.5 else 0
    for _i in range(later):
        now[0] += 1000 + int(r() * 2)
        subject = pick(anchors) if r() < 0.6 else pick(keys)
        typ = "genesis" if r() < 0.6 else "succession"
        endorser = pick([k for k in keys if k != subject])
        activated_at = t()
        add(typ, subject, endorser, activated_at, r())
    statements.sort(key=lambda x: (x["created_us"], x["id"]))
    distrusted: list[tuple[int, str | None]] = []
    if r() < 0.5:
        # A generator keeps the draw order: the filter, then the cutoff, key by key.
        distrusted.extend((k, None if r() < 0.5 else t()) for k in keys if r() < 0.25)
    kept = [k for k in keys if r() < 0.8]
    rows = [{"key": k, "status": "retired" if r() < 0.3 else "active", "activated_at": t(), "retired_at": t()} for k in kept]
    return _Scenario(statements, anchors, distrusted, rows)


def _walk(sc: _Scenario, statements: list[dict[str, Any]] | None = None, *, micro: bool = False) -> KeyTrust:
    """The scenario as a dump (write order, millisecond ``created_at``), or with
    ``micro`` its statements in the order given at the microsecond write times
    a key document publishes."""
    return compute_key_trust(
        keys=[
            TrustKeyInput(
                key_id=POOL[k["key"]].kid,
                public_key=POOL[k["key"]].public_key,
                algorithm=POOL[k["key"]].alg,
                status=k["status"],
                activated_at=_to_ms(k["activated_at"]),
                retired_at=_to_ms(k["retired_at"]) if k["status"] == "retired" else None,
                source="dump",
            )
            for k in sc.rows
        ],
        statements=[
            KeyStatementInput(
                id=s["id"],
                kind=s["kind"],
                subject_key_id=POOL[s["subject"]].kid,
                endorser_key_id=None if s["endorser"] is None else POOL[s["endorser"]].kid,
                endorser_column=True,
                source="dump",
                cose=s["cose"],
                created_at=s["created_us"] if micro else _iso(s["created_ms"]),
            )
            for s in (sc.statements if statements is None else statements)
        ],
        trust_anchors=[f"sha256:{POOL[k].digest}" for k in sc.anchors],
        distrusted_keys=[DistrustedKey(POOL[k].digest, cutoff) for k, cutoff in sc.distrusted],
    )


def _verdict(trust: KeyTrust) -> dict[str, Any]:
    """Keyed by pool index, window drift left out (the engine compares a column
    at the microsecond precision its database holds; a dump carries
    milliseconds)."""
    trusted = sorted(_INDEX_OF_DIGEST[d] for d in trust.trusted)
    windows: dict[str, list[str | None]] = {}
    for i in trusted:
        w = trust.by_digest.get(POOL[i].digest)
        # The engine folds a distrust cutoff into the window's upper edge; the
        # port carries it apart from the signed retirement, so compare the
        # edge entries are graded against.
        windows[str(i)] = [w.activated_at if w else None, (w.distrust_cutoff or w.retired_at) if w else None]
    findings = sorted(
        f"{f.code}|{f.statement_id or ''}|{'' if f.key_id is None else _INDEX_OF_KID.get(f.key_id, f.key_id)}"
        for f in trust.findings
        if f.code != "CHAIN_KEY_WINDOW_DRIFT"
    )
    accounted = sorted(
        f"{n.statement_id or ''}|{'' if n.key_id is None else _INDEX_OF_KID.get(n.key_id, n.key_id)}"
        for n in trust.accounted
    )
    spans = {
        str(_INDEX_OF_DIGEST[d]): [span.cutoff, span.retired_at]
        for d, span in sorted(trust.distrust_spans.items(), key=lambda item: _INDEX_OF_DIGEST[item[0]])
    }
    return {"trusted": trusted, "windows": windows, "findings": findings, "accounted": accounted, "spans": spans}


def _at_milliseconds(v: dict[str, Any]) -> dict[str, Any]:
    """A verdict at the millisecond precision a dump's write times carry. A
    retirement bound is capped at its closure's write time, which a dump gives
    in milliseconds and the engine holds in microseconds; every entry and
    statement is graded against it in milliseconds, so that is where the two
    must agree."""

    def ms(x: str | None) -> str | None:
        return None if x is None else f"{x[:23]}Z"

    def pair(r: dict[str, list[str | None]]) -> dict[str, list[str | None]]:
        return {k: [ms(a), ms(b)] for k, (a, b) in r.items()}

    return {**v, "windows": pair(v["windows"]), "spans": pair(v["spans"])}


def _retired_at_of(st: dict[str, Any]) -> str | None:
    """The ``retiredAt`` a closure signs."""
    if st["kind"] != "closure":
        return None
    envelope = cbor2.loads(st["cose"][0])
    payload = cbor2.loads(envelope.value[2])
    return payload["subject"].get("retiredAt")


def test_the_walk_trusts_signs_and_finds_what_the_engine_recorded_on_every_registry() -> None:
    verdicts: dict[str, Any] = _RECORDED["verdicts"]
    assert len(verdicts) >= 1000
    diverged: list[str] = []
    for seed, recorded in verdicts.items():
        sc = _scenario(int(seed))
        got = _at_milliseconds(_verdict(_walk(sc)))
        want = _at_milliseconds(recorded)
        # A closure dated after its write time within the same millisecond:
        # the engine sees it in microseconds, a dump's write time cannot show it.
        hidden = {
            st["id"]
            for st in sc.statements
            if (r := _retired_at_of(st)) is not None and r > st["created_us"] and r[:23] == st["created_us"][:23]
        }
        want["findings"] = [
            f
            for f in want["findings"]
            if not (f.startswith("KEY_CLOSURE_INVALID|") and f.split("|")[1] in hidden and f not in got["findings"])
        ]
        if got != want:
            diverged.append(f"seed {seed}: engine {want}, walk {got}")
    assert diverged[:5] == []


def test_the_walk_takes_the_write_order_from_created_at_and_id_whatever_order_the_statements_arrive_in() -> None:
    diverged: list[str] = []
    for seed, want in _RECORDED["verdicts"].items():
        r = _prng(int(seed) ^ 0x5EED)
        sc = _scenario(int(seed))
        shuffled = [x for _k, x in sorted(((r(), x) for x in sc.statements), key=lambda p: p[0])]
        if (got := _verdict(_walk(sc, shuffled, micro=True))) != want:
            diverged.append(f"seed {seed}: engine {want}, walk {got}")
    assert diverged[:5] == []


# --- a walk over the key document the engine publishes ---


def _document_of(sc: _Scenario, published: list[dict[str, Any]]) -> dict[str, Any]:
    """The ``/v1/verification-keys`` document the engine publishes for a scenario."""
    by_id = {s["id"]: s for s in sc.statements}
    return {
        "keyStatementFormat": "application/vnd.agledger.key-statement+cbor",
        "data": [
            {
                "keyId": POOL[k["key"]].kid,
                "publicKey": POOL[k["key"]].public_key,
                "algorithm": POOL[k["key"]].alg,
                "status": "active" if k["retiredAt"] is None else "retired",
                "activatedAt": k["activatedAt"],
                "retiredAt": k["retiredAt"],
                **({"distrustedFrom": k["distrustedFrom"]} if "distrustedFrom" in k else {}),
                "statements": [
                    {
                        "id": i,
                        "kind": by_id[i]["kind"],
                        "createdAt": by_id[i]["created_us"],
                        "cose": [base64.b64encode(b).decode() for b in by_id[i]["cose"]],
                    }
                    for i in k["statements"]
                ],
            }
            for k in published
        ],
    }


def _walk_document(
    sc: _Scenario,
    published: list[dict[str, Any]],
    distrusted: list[DistrustedKey] | None = None,
) -> KeyTrust:
    keys, statements = key_statements_from_verification_keys(
        _document_of(sc, published)
    )
    return compute_key_trust(
        keys=keys,
        statements=statements,
        trust_anchors=[f"sha256:{POOL[k].digest}" for k in sc.anchors],
        distrusted_keys=(
            [DistrustedKey(POOL[k].digest, cutoff) for k, cutoff in sc.distrusted]
            if distrusted is None
            else distrusted
        ),
    )


def test_a_document_walk_agrees_with_the_engine_s_own_walk_over_that_document() -> None:
    diverged = [
        f"seed {seed}: engine {want}, walk {got}"
        for seed, want in _RECORDED["documents"].items()
        if (got := _verdict(_walk_document(_scenario(int(seed)), _RECORDED["published"][seed]))) != want
    ]
    assert diverged[:5] == []


def test_a_document_walk_never_trusts_a_key_the_engine_does_not_and_flags_any_window_it_grades_more_loosely() -> None:
    wrong: list[str] = []
    for seed, want in _RECORDED["verdicts"].items():
        sc = _scenario(int(seed))
        published = _RECORDED["published"][seed]
        trust = _walk_document(sc, published)
        got = _verdict(trust)
        # Only a finding on the listed key's window excuses a looser one.
        flagged = {
            f.key_id
            for f in trust.findings
            if f.statement_id is None and f.code in ("CHAIN_KEY_WINDOW_DRIFT", "KEY_CLOSURE_INVALID")
        }
        for k in got["trusted"]:
            if k not in want["trusted"]:
                wrong.append(f"seed {seed}: key {k} trusted, the engine does not")
            elif (
                any(p["key"] == k for p in published)
                and got["windows"][str(k)] != want["windows"][str(k)]
                and POOL[k].kid not in flagged
            ):
                wrong.append(f"seed {seed}: key {k} window {got['windows'][str(k)]}, engine {want['windows'][str(k)]}")
    assert wrong[:5] == []


def test_a_document_walk_agrees_with_the_engine_when_every_statement_verifies_every_anchor_is_published_and_no_key_is_distrusted() -> None:
    agreed = 0
    wrong: list[str] = []
    for seed, want in _RECORDED["verdicts"].items():
        sc = _scenario(int(seed))
        published = _RECORDED["published"][seed]
        if not all(any(p["key"] == a for p in published) for a in sc.anchors):
            continue
        # A document's write times are unsigned, so every edge out of a
        # distrusted key in it is void, where the engine keeps what the key
        # stored before its cutoff: narrower, which the test above holds.
        if sc.distrusted:
            continue
        trust = _walk_document(sc, published)
        if trust.statements.invalid > 0:
            continue
        got = _verdict(trust)
        listed = sorted(p["key"] for p in published)
        same = (
            got["trusted"] == listed
            and all(got["windows"][str(k)] == want["windows"][str(k)] for k in listed)
            and not any(f.statement_id is None for f in trust.findings)
        )
        if same:
            agreed += 1
        else:
            wrong.append(f"seed {seed}")
    assert wrong[:5] == []
    assert agreed >= 200


def test_a_document_walk_reads_distrusted_from_only_into_wording() -> None:
    """With or without the ``distrustedFrom`` the engine publishes, and whatever
    distrust entries the walk is given, the same keys, windows and findings."""
    reworded = 0
    listed = 0
    wrong: list[str] = []

    def findings_of(t: KeyTrust) -> list[tuple[str, str | None, str | None]]:
        return [(f.code, f.key_id, f.statement_id) for f in t.findings]

    for seed in _RECORDED["verdicts"]:
        sc = _scenario(int(seed))
        published: list[dict[str, Any]] = _RECORDED["published"][seed]
        if not any("distrustedFrom" in p for p in published):
            continue
        listed += 1
        without = [
            {k: v for k, v in p.items() if k != "distrustedFrom"} for p in published
        ]
        r = _prng(int(seed) ^ 0xD157)
        # The engine's entries, none, and each moved to a random instant or none.
        shifted = [
            DistrustedKey(
                POOL[k].digest,
                None
                if r() < 0.2
                else f"2026-01-01T00:00:{int(r() * 60):02d}.{int(r() * 1e6):06d}Z",
            )
            for k, _c in sc.distrusted
        ]
        for distrusted in (
            [DistrustedKey(POOL[k].digest, c) for k, c in sc.distrusted],
            [],
            shifted,
        ):
            a = _walk_document(sc, published, distrusted)
            b = _walk_document(sc, without, distrusted)
            if (_verdict(a), findings_of(a)) != (_verdict(b), findings_of(b)):
                wrong.append(
                    f"seed {seed}: with distrustedFrom {findings_of(a)}, without {findings_of(b)}"
                )
            if any(
                f.detail != g.detail
                and "is listed as the Server's distrust cutoff" in f.detail
                for f, g in zip(a.findings, b.findings, strict=False)
            ):
                reworded += 1
    assert wrong[:5] == []
    assert listed >= 100
    assert reworded >= 100


def test_a_document_walk_needs_the_later_admissions_the_engine_publishes() -> None:
    moved = 0
    for seed in _RECORDED["verdicts"]:
        sc = _scenario(int(seed))
        kind_of = {s["id"]: s["kind"] for s in sc.statements}
        published = _RECORDED["published"][seed]
        first_only: list[dict[str, Any]] = []
        for k in published:
            admitted = False
            kept: list[str] = []
            for i in k["statements"]:
                if kind_of[i] == "closure":
                    kept.append(i)
                elif not admitted:
                    admitted = True
                    kept.append(i)
            first_only.append({**k, "statements": kept})
        every = _verdict(_walk_document(sc, published))
        first = _verdict(_walk_document(sc, first_only))
        if (every["trusted"], every["windows"]) != (first["trusted"], first["windows"]):
            moved += 1
    assert moved >= 50


def _looser(got: list[str | None], base: list[str | None]) -> bool:
    """Whether window ``got`` admits an instant ``base`` does not."""
    (ga, gr), (ba, br) = got, base
    earlier_start = ba is not None and (ga is None or ga < ba)
    later_end = br is not None and (gr is None or gr > br)
    return earlier_start or later_end


def test_a_document_with_edited_write_times_gets_nothing_from_a_distrusted_keys_statements() -> None:
    """Whatever ``createdAt`` and ``id`` a document gives its statements, what
    a distrusted key signed confers nothing: the walk trusts no key, and grades
    no other key's window more loosely, than the same statements read as dump
    rows with every distrusted key distrusted from the epoch."""
    epoch = "1970-01-01T00:00:00.000000Z"
    wrong: list[str] = []
    checked = 0
    for seed in _RECORDED["verdicts"]:
        sc = _scenario(int(seed))
        if not sc.distrusted:
            continue
        checked += 1
        r = _prng(int(seed) ^ 0xED17)
        keys = [TrustKeyInput(key_id=POOL[k["key"]].kid, public_key=POOL[k["key"]].public_key) for k in sc.rows]
        anchors = [f"sha256:{POOL[k].digest}" for k in sc.anchors]
        distrusted = {POOL[k].digest for k, _c in sc.distrusted}
        for _ in range(4):
            # Any time and any id the holder of a leaked key cares to write.
            edited = [
                KeyStatementInput(
                    id=f"{int(r() * 0x100000000):08x}-0000-4000-8000-000000000000",
                    kind=s["kind"],
                    subject_key_id=POOL[s["subject"]].kid,
                    cose=s["cose"],
                    created_at=_us(_BASE + int(r() * 40) * 1000, int(r() * 1000)),
                )
                for s in sc.statements
            ]
            got = compute_key_trust(
                keys=keys,
                statements=edited,
                trust_anchors=anchors,
                distrusted_keys=[DistrustedKey(POOL[k].digest, c) for k, c in sc.distrusted],
            )
            base = compute_key_trust(
                keys=keys,
                statements=[dataclasses.replace(st, source="dump") for st in edited],
                trust_anchors=anchors,
                distrusted_keys=[DistrustedKey(POOL[k].digest, epoch) for k, _c in sc.distrusted],
            )
            for d in got.trusted:
                if d not in base.trusted:
                    wrong.append(f"seed {seed}: key {_INDEX_OF_DIGEST[d]} trusted")
                elif d not in distrusted:
                    g, b = got.by_digest[d], base.by_digest[d]
                    if _looser([g.activated_at, g.distrust_cutoff or g.retired_at], [b.activated_at, b.distrust_cutoff or b.retired_at]):
                        wrong.append(f"seed {seed}: key {_INDEX_OF_DIGEST[d]} window looser")
    assert checked >= 300
    assert wrong[:5] == []


def test_with_every_closed_key_distrusted_an_edited_document_trusts_nothing_the_signed_order_would_not() -> None:
    """Any ``createdAt`` and ``id`` on a published document, rows copied under
    new ids, and every key a closure retires distrusted (from a random instant
    or with none): the walk trusts no key and grades no window more loosely
    than the signed-order walk of the same statements."""
    wrong: list[str] = []
    distrusted_edges = 0
    for seed in _RECORDED["verdicts"]:
        sc = _scenario(int(seed))
        r = _prng(int(seed) ^ 0xED17)
        doc = _document_of(sc, _RECORDED["published"][seed])
        every = [st for k in doc["data"] for st in k["statements"]]
        if not every:
            continue
        by_id = {s["id"]: s for s in sc.statements}

        def any_time() -> str:
            if r() < 0.3:
                return "2020-01-01T00:00:00.000000Z"
            return f"2026-01-01T00:00:{int(r() * 60):02d}.{int(r() * 1e6):06d}Z"

        def any_id() -> str:
            if r() < 0.2:
                return every[int(r() * len(every))]["id"]
            return f"{int(r() * 0xFFFFFFFF):08x}-0000-4000-8000-000000000000"

        edited = copy.deepcopy(doc)
        for k in edited["data"]:
            rows = [
                {**st, "id": any_id() if r() < 0.5 else st["id"], "createdAt": any_time() if r() < 0.7 else st["createdAt"]}
                for st in k["statements"]
            ]
            if rows and r() < 0.2:
                rows.append({**rows[int(r() * len(rows))], "id": any_id(), "createdAt": any_time()})
            k["statements"] = rows
        stripped = copy.deepcopy(doc)
        for k in stripped["data"]:
            k["statements"] = [{"kind": st["kind"], "cose": st["cose"]} for st in k["statements"]]
        closed = {by_id[st["id"]]["subject"] for st in every if st["kind"] == "closure"}
        for s in sc.statements:
            if r() < 0.2:
                closed.add(s["subject"])
        distrusted = [
            DistrustedKey(POOL[k].digest, None if r() < 0.3 else f"2026-01-01T00:00:{int(r() * 20):02d}.000000Z")
            for k in closed
        ]
        if distrusted:
            distrusted_edges += 1

        def walk(d: dict[str, Any], distrusted: list[DistrustedKey] = distrusted) -> KeyTrust:
            keys, statements = key_statements_from_verification_keys(d)
            return compute_key_trust(
                keys=keys,
                statements=statements,
                trust_anchors=[f"sha256:{POOL[k].digest}" for k in sc.anchors],
                distrusted_keys=distrusted,
            )

        written, signed = walk(edited), walk(stripped)
        assert (written.order, signed.order) == ("written", "signed")
        for d in written.trusted:
            if d not in signed.trusted:
                wrong.append(f"seed {seed}: {d[:16]} trusted only under the edited times")
                continue
            w, b = written.by_digest[d], signed.by_digest[d]
            if _looser([w.activated_at, w.distrust_cutoff or w.retired_at], [b.activated_at, b.distrust_cutoff or b.retired_at]):
                wrong.append(f"seed {seed}: {d[:16]} window wider than the signed order's")
    assert distrusted_edges >= 500
    assert wrong[:5] == []
