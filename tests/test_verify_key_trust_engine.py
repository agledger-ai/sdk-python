"""The walk against the engine's own verdicts on the same random registries:
statements of every kind in any signer order, write times and signed instants
that tie, duplicated rows, and distrusted keys with and without a cutoff. The
verdicts in ``fixtures/key-trust-engine.json`` were recorded from the engine's
``computeKeyTrust`` by verify-core's ``scripts/record-key-trust-engine.mts``,
and verify-core holds its walk to the same file. The scenarios are regenerated
here from the seed exactly as verify-core's ``key-trust-fuzz.ts`` generates
them, so a divergence in either the generator or the walk fails this test."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agledger.verify.key_statements import (
    DistrustedKey,
    KeyStatementInput,
    KeyTrust,
    TrustKeyInput,
    compute_key_trust,
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
    now = _BASE
    idn = [0]

    def next_id() -> str:
        idn[0] += 1
        return f"s{idn[0]}"

    def t() -> str:
        ms = _BASE + int(r() * 20) * 1000
        ms += int(r() * 3)
        return _us(ms, int(r() * 1000))

    statements: list[dict[str, Any]] = []
    n = 3 + int(r() * 12)
    for _i in range(n):
        step = int(r() * 3) * 1000
        now += step + (0 if r() < 0.2 else 1)
        typ = pick(["genesis", "succession", "succession", "closure", "closure"])
        subject = pick(keys)
        endorser = pick([k for k in keys if k != subject])
        activated_at = t()
        retired_at = t()
        if typ == "genesis":
            signers = [subject]
        elif typ == "succession":
            signers = [endorser, subject] if r() < 0.9 else [endorser] if r() < 0.5 else [subject, endorser]
        else:
            signers = [endorser]
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
        st = {
            "id": next_id(),
            "kind": typ,
            "subject": subject,
            "endorser": endorser if typ != "genesis" else None,
            "cose": [sign_statement(data, POOL[k]) for k in signers],
            "created_ms": now,
        }
        statements.append(st)
        if r() < 0.1:
            statements.append({**st, "id": f"dup-{next_id()}", "created_ms": now + 1})
    first = pick(keys)
    anchors = list(dict.fromkeys([first, *([pick(keys)] if r() < 0.3 else [])]))
    distrusted: list[tuple[int, str | None]] = []
    if r() < 0.5:
        # A generator keeps the draw order: the filter, then the cutoff, key by key.
        distrusted.extend((k, None if r() < 0.5 else t()) for k in keys if r() < 0.25)
    kept = [k for k in keys if r() < 0.8]
    rows = [{"key": k, "status": "retired" if r() < 0.3 else "active", "activated_at": t(), "retired_at": t()} for k in kept]
    return _Scenario(statements, anchors, distrusted, rows)


def _walk(sc: _Scenario) -> KeyTrust:
    return compute_key_trust(
        keys=[
            TrustKeyInput(
                key_id=POOL[k["key"]].kid,
                public_key=POOL[k["key"]].public_key,
                algorithm=POOL[k["key"]].alg,
                status=k["status"],
                activated_at=_to_ms(k["activated_at"]),
                retired_at=_to_ms(k["retired_at"]) if k["status"] == "retired" else None,
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
                cose=s["cose"],
                created_at=_iso(s["created_ms"]),
            )
            for s in sc.statements
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
        windows[str(i)] = [w.activated_at if w else None, w.retired_at if w else None]
    findings = sorted(
        f"{f.code}|{f.statement_id or ''}|{'' if f.key_id is None else _INDEX_OF_KID.get(f.key_id, f.key_id)}"
        for f in trust.findings
        if f.code != "CHAIN_KEY_WINDOW_DRIFT"
    )
    return {"trusted": trusted, "windows": windows, "findings": findings}


def test_the_walk_trusts_signs_and_finds_what_the_engine_recorded_on_every_registry() -> None:
    verdicts: dict[str, Any] = _RECORDED["verdicts"]
    assert len(verdicts) >= 1000
    diverged = [
        f"seed {seed}: engine {want}, walk {got}"
        for seed, want in verdicts.items()
        if (got := _verdict(_walk(_scenario(int(seed))))) != want
    ]
    assert diverged[:5] == []
