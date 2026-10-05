"""``distrustedFrom`` on a listed key: the Server's VAULT_DISTRUSTED_KEYS
instant, where its published ``retiredAt`` was cut. It only words the finding
the window check makes anyway; every case below makes the same findings, by
code, key and statement, and the same trusted keys and windows, with the field
as without it. A port of verify-core's ``distrusted-from.test.ts``."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from agledger.verify import verify_export
from agledger.verify.cli import (  # pyright: ignore[reportPrivateUsage]
    _dump_report_with_flags,
    _flag_wording,
    run_cli,
)
from agledger.verify.failures import suggestion
from agledger.verify.key_statements import (
    DistrustedKey,
    KeyRegistryFinding,
    KeyStatementInput,
    KeyTrust,
    KeyTrustNote,
    KeyTrustReport,
    TrustKeyInput,
    compute_key_trust,
    key_statements_from_verification_keys,
)
from agledger.verify.types import (
    AccountedEntry,
    Failure,
    TenantAdminReadsReport,
    VaultChainsReport,
    VerifyReport,
)

from .key_statement_helpers import (
    T0,
    T1,
    T2,
    TestKey,
    as_document,
    make_key,
    ms,
    statement,
)

#: Between the successor's admission (T1) and the closure it signed (T2).
CUT = "2026-09-02T12:00:00.123456Z"
LATER = "2026-09-02T18:00:00.000000Z"
EARLIER = "2026-09-02T06:00:00.000000Z"
AFTER_CLOSURE = "2026-09-03T06:00:00.000000Z"


def listed(
    k: TestKey,
    activated_at: str,
    retired_at: str | None,
    distrusted_from: str | None = None,
) -> TrustKeyInput:
    """A key as a key document lists it."""
    return TrustKeyInput(
        key_id=k.kid,
        public_key=k.public_key,
        algorithm=k.alg,
        status="active" if retired_at is None else "retired",
        activated_at=ms(activated_at),
        retired_at=None if retired_at is None else ms(retired_at),
        distrusted_from=distrusted_from,
    )


@dataclass
class Rotation:
    k: TestKey
    f: TestKey
    statements: list[KeyStatementInput]


def rotation(closed: bool = True) -> Rotation:
    """The old key ``k`` hands over to ``f``, which retires it at T2 (or never)."""
    k, f = make_key(), make_key()
    stored = [
        statement("genesis", k, signers=[k], activated_at=T0, created_at=T0),
        statement(
            "succession", f, endorser=k, signers=[k, f], activated_at=T1, created_at=T1
        ),
    ]
    if closed:
        stored.append(
            statement(
                "closure", k, endorser=f, signers=[f], retired_at=T2, created_at=T2
            )
        )
    return Rotation(k, f, as_document(stored))


def walk(
    r: Rotation, k_listing: TrustKeyInput, distrusted: list[DistrustedKey] | None = None
) -> KeyTrust:
    return compute_key_trust(
        keys=[k_listing, listed(r.f, T1, None)],
        statements=r.statements,
        trust_anchors=[f"sha256:{r.f.digest}"],
        distrusted_keys=distrusted,
    )


def lead(k: TestKey, signed: str) -> str:
    """The wording the walk gives a listed retirement the Server's distrust entry cut."""
    return f"retiredAt {ms(CUT)} is listed as the Server's distrust cutoff for {k.kid} (distrustedFrom {CUT}), and {signed}"


def caution(k: TestKey) -> str:
    return (
        "The listing's instant is its unsigned word, so until the Server's operator confirms the entry, read the "
        f"listed retirement as unexplained. Off a dump the entry also voids every admission {k.kid} signed, so a key "
        "it admitted that nothing else reaches is no longer trusted and its window no longer graded."
    )


def missing(k: TestKey, signed: str) -> str:
    return (
        f"{lead(k, signed)}: the listing says the Server distrusts the key from that instant (VAULT_DISTRUSTED_KEYS), "
        f"and this walk was given no distrust entry for it. If the operator confirms it, give distrustedKeys "
        f"sha256:{k.digest}@{CUT}. {caution(k)}"
    )


def disagree(k: TestKey, signed: str, given: str) -> str:
    return (
        f"{lead(k, signed)}: the distrust entry given for it ({given}) and the one the listing says the Server applies "
        f"(VAULT_DISTRUSTED_KEYS, from {CUT}) disagree. Confirm the instant with the Server's operator. {caution(k)}"
    )


def shape(t: KeyTrust) -> dict[str, Any]:
    return {
        "findings": [(f.code, f.key_id, f.statement_id) for f in t.findings],
        "trusted": sorted(t.trusted),
        "windows": [
            (e.spki_sha256, e.activated_at, e.retired_at, e.distrust_cutoff)
            for e in t.by_digest.values()
        ],
    }


@dataclass
class Both:
    with_from: KeyTrust
    without: KeyTrust
    added: list[KeyTrustNote]


def both(
    r: Rotation,
    retired_at: str | None,
    frm: str,
    distrusted: list[DistrustedKey] | None = None,
) -> Both:
    """The walk with and without the listing's distrusted_from, which must differ only in wording."""
    with_from = walk(r, listed(r.k, T0, retired_at, frm), distrusted)
    without = walk(r, listed(r.k, T0, retired_at), distrusted)
    assert shape(with_from) == shape(without)
    # Every note the walk makes without the field it makes with it; ``added`` is
    # what the field says on top.
    assert all(n in with_from.notes for n in without.notes)
    return Both(
        with_from, without, [n for n in with_from.notes if n not in without.notes]
    )


def test_cut_at_that_instant_with_no_entry_given_names_the_server_s_distrust_entry_the_walk_lacks_and_still_fails() -> (
    None
):
    r = rotation()
    b = both(r, CUT, CUT)
    assert [(f.code, f.key_id, f.statement_id) for f in b.with_from.findings] == [
        ("CHAIN_KEY_WINDOW_DRIFT", r.k.kid, None)
    ]
    assert b.with_from.findings[0].detail == missing(
        r.k, f"the retirement its closures sign is {T2}"
    )
    assert b.with_from.findings[0].distrusted_from == CUT
    assert (
        b.without.findings[0].detail
        == f"retiredAt {ms(CUT)} differs from the signed {T2}"
    )
    assert b.without.findings[0].distrusted_from is None
    assert b.added == []


def test_with_the_entry_it_names_passes_as_it_did() -> None:
    r = rotation()
    b = both(r, CUT, CUT, [DistrustedKey(r.k.digest, CUT)])
    assert b.with_from.findings == []
    assert b.added == []


@pytest.mark.parametrize("given", [LATER, AFTER_CLOSURE])
def test_with_an_entry_at_a_later_instant_than_the_server_s_says_the_two_disagree(
    given: str,
) -> None:
    """On either side of the signed retirement."""
    r = rotation()
    b = both(r, CUT, CUT, [DistrustedKey(r.k.digest, given)])
    assert [(f.code, f.key_id) for f in b.with_from.findings] == [
        ("CHAIN_KEY_WINDOW_DRIFT", r.k.kid)
    ]
    assert b.with_from.findings[0].detail == disagree(
        r.k, f"the retirement its closures sign is {T2}", f"from {given}"
    )
    assert b.added == []


def test_with_an_entry_in_the_same_millisecond_but_another_microsecond_says_the_two_disagree_in_a_note() -> (
    None
):
    """The window check reads milliseconds, so it fails nothing; the two
    instants are still compared at the microsecond the entries carry."""
    r = rotation()
    given = "2026-09-02T12:00:00.123000Z"
    b = both(r, CUT, CUT, [DistrustedKey(r.k.digest, given)])
    assert b.with_from.findings == []
    assert [
        n.detail[: len(f"distrustedKeys gives {r.k.kid} the instant {given}")]
        for n in b.added
    ] == [f"distrustedKeys gives {r.k.kid} the instant {given}"]


def test_with_an_entry_that_has_no_instant_says_the_two_disagree() -> None:
    r = rotation()
    b = both(r, CUT, CUT, [DistrustedKey(r.k.digest, None)])
    assert [f.code for f in b.with_from.findings] == ["CHAIN_KEY_WINDOW_DRIFT"]
    assert b.with_from.findings[0].detail == disagree(
        r.k, f"the retirement its closures sign is {T2}", "with no instant"
    )


def test_with_an_entry_at_an_earlier_instant_which_fails_nothing_on_the_window_says_so_in_a_note() -> (
    None
):
    r = rotation()
    b = both(r, CUT, CUT, [DistrustedKey(r.k.digest, EARLIER)])
    assert b.with_from.findings == []
    assert b.added == [
        KeyTrustNote(
            r.k.kid,
            None,
            f"distrustedKeys gives {r.k.kid} the instant {EARLIER}, and the listing says the Server distrusts it from "
            f"{CUT} (distrustedFrom, VAULT_DISTRUSTED_KEYS): the auditor's entry and the one the listing gives "
            "disagree, so what the key signed between the two instants is graded differently here than on the "
            "Server. Confirm the instant with the Server's operator.",
        )
    ]


def test_cut_where_no_closure_retires_the_key_the_key_closure_invalid_names_the_missing_entry() -> (
    None
):
    """And the entry clears it."""
    r = rotation(closed=False)
    b = both(r, CUT, CUT)
    assert [(f.code, f.key_id) for f in b.with_from.findings] == [
        ("KEY_CLOSURE_INVALID", r.k.kid)
    ]
    assert b.with_from.findings[0].detail == missing(
        r.k, "no closure this walk could verify retires it"
    )
    assert both(r, CUT, CUT, [DistrustedKey(r.k.digest, CUT)]).with_from.findings == []


def test_keeps_the_drift_wording_where_the_listing_is_not_the_server_s_instant_or_the_instant_does_not_parse() -> (
    None
):
    r = rotation()
    # Listed earlier than distrustedFrom.
    assert [f.detail for f in both(r, EARLIER, CUT).with_from.findings] == [
        f"retiredAt {ms(EARLIER)} differs from the signed {T2}"
    ]
    # distrustedFrom after the signed retirement, listed at it: honest, nothing to say.
    assert both(r, T2, AFTER_CLOSURE).with_from.findings == []
    # Listed at distrustedFrom, which is later than the retirement the walk signs.
    assert [
        f.detail for f in both(r, AFTER_CLOSURE, AFTER_CLOSURE).with_from.findings
    ] == [f"retiredAt {ms(AFTER_CLOSURE)} differs from the signed {T2}"]
    # Not strict RFC 3339 (no offset).
    assert [
        f.detail for f in both(r, CUT, "2026-09-02T12:00:00.123456").with_from.findings
    ] == [f"retiredAt {ms(CUT)} differs from the signed {T2}"]
    # A key the walk does not trust is never graded, whatever it lists.
    stranger = make_key()
    t = compute_key_trust(
        keys=[listed(stranger, T0, CUT, CUT)],
        statements=r.statements,
        trust_anchors=[f"sha256:{r.f.digest}"],
    )
    assert t.findings == []


def test_is_read_from_a_key_document() -> None:
    r = rotation()
    keys, _statements = key_statements_from_verification_keys(
        {
            "data": [
                {
                    "keyId": r.k.kid,
                    "publicKey": r.k.public_key,
                    "status": "retired",
                    "activatedAt": ms(T0),
                    "retiredAt": ms(CUT),
                    "distrustedFrom": CUT,
                },
                {
                    "keyId": r.f.kid,
                    "publicKey": r.f.public_key,
                    "status": "active",
                    "activatedAt": ms(T1),
                    "retiredAt": None,
                },
                {
                    "keyId": "x",
                    "publicKey": r.f.public_key,
                    "distrustedFrom": 1788480000,
                },
            ]
        }
    )
    assert [k.distrusted_from for k in keys] == [CUT, None, None]


# --- a live export after a dated distrust entry ---

LIVE = Path(__file__).parent / "fixtures" / "live-2.0.0" / "export-dated-distrust.json"
F = "sha256:78e7bba47a2dccdb1dbf4f2dc81dc58a5c58735abe480de49d05081d3452aa3a"
K = "b649db0ec7c5c0fd921c2cb4d40466d91f4d98252dad2f7c0243851167b2d09e"
FROM = "2026-10-05T23:03:51.537314Z"


def _load() -> dict[str, Any]:
    """An unmodified agledger-api 2.0 audit export of a record its first key K
    signed, taken after the Server retired K with force from its successor F
    and was restarted with VAULT_DISTRUSTED_KEYS=sha256:<K>@<instant>, an
    instant before that retirement: signingKeyWindows lists K retired at the
    instant, with distrustedFrom."""
    return json.loads(LIVE.read_text())


def test_a_live_export_pinned_on_f_alone_fails_naming_the_server_s_entry() -> None:
    """With that entry, passes; with another instant, says they disagree."""
    windows = _load()["exportMetadata"]["signingKeyWindows"]
    assert windows[K[:16]] == {
        "activatedAt": "2026-10-05T23:03:18.193Z",
        "retiredAt": "2026-10-05T23:03:51.537Z",
        "distrustedFrom": FROM,
    }

    pin_only = verify_export(_load(), trust_anchors=[F])
    assert pin_only.valid is False
    assert pin_only.broken_at is not None
    assert (pin_only.broken_at.position, pin_only.broken_at.code) == (
        0,
        "CHAIN_KEY_WINDOW_DRIFT",
    )
    assert (
        f"this walk was given no distrust entry for it. If the operator confirms it, give distrustedKeys "
        f"sha256:{K}@{FROM}." in (pin_only.broken_at.detail or "")
    )

    matching = verify_export(
        _load(), trust_anchors=[F], distrusted_keys=[f"sha256:{K}@{FROM}"]
    )
    assert (matching.valid, matching.verdict) == (True, "trusted")
    assert matching.key_trust.notes == []

    later = verify_export(
        _load(), trust_anchors=[F], distrusted_keys=[f"sha256:{K}@2026-10-05T23:04:00Z"]
    )
    assert later.valid is False
    assert later.broken_at is not None
    assert (
        "the distrust entry given for it (from 2026-10-05T23:04:00.000000Z) and the one the listing says the Server "
        f"applies (VAULT_DISTRUSTED_KEYS, from {FROM}) disagree"
        in (later.broken_at.detail or "")
    )

    # Without the field the export fails at the same place, worded as drift.
    stripped = copy.deepcopy(_load())
    del stripped["exportMetadata"]["signingKeyWindows"][K[:16]]["distrustedFrom"]
    bare = verify_export(stripped, trust_anchors=[F])
    assert bare.broken_at is not None
    assert (bare.broken_at.position, bare.broken_at.code) == (
        0,
        "CHAIN_KEY_WINDOW_DRIFT",
    )
    assert (
        bare.broken_at.detail
        == "retiredAt 2026-10-05T23:03:51.537Z differs from the signed 2026-10-05T23:04:11.954995Z"
    )


TAMPER = "Treat the registry as tampered"


def _text(capsys: pytest.CaptureFixture[str], path: Path) -> tuple[int, str]:
    code = run_cli([str(path), "--trust-anchor", F])
    return code, capsys.readouterr().out


def test_agledger_verify_leaves_the_tamper_advice_off_a_finding_worded_as_the_server_s_entry(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The finding still fails, and its remedy keeps the rest of the code's
    suggestion, including that the listing's word stays tampering until the
    operator confirms it."""
    assert TAMPER in suggestion("CHAIN_KEY_WINDOW_DRIFT")
    code, out = _text(capsys, LIVE)
    assert code == 1
    remedies = [line for line in out.splitlines() if line.strip().startswith("->")]
    assert len(remedies) == 2  # under the key-trust finding and under broken-at
    for line in remedies:
        assert TAMPER not in line
        assert (
            "it stays tampering until the Server's operator confirms the entry." in line
        )
        assert "Compare it with the Server's own scan (key_window_drift)." in line
    # The advice names the flag, as @agledger/verify words it.
    assert (
        f"If the operator confirms it, give --distrusted-key sha256:{K}@{FROM}." in out
    )
    assert "distrustedKeys" not in out


def test_agledger_verify_json_names_the_flag_and_leaves_the_library_result_in_option_names(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        run_cli(
            [
                str(LIVE),
                "--trust-anchor",
                F,
                "--distrusted-key",
                f"sha256:{K}@2026-10-05T23:03:48Z",
                "-f",
                "json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    note = "--distrusted-key gives b649db0ec7c5c0fd the instant 2026-10-05T23:03:48.000000Z, and the listing says"
    assert [n["detail"][: len(note)] for n in report["keyTrust"]["notes"]] == [note]
    library = verify_export(_load(), trust_anchors=[F])
    assert library.broken_at is not None
    assert f"give distrustedKeys sha256:{K}@{FROM}." in (library.broken_at.detail or "")


@pytest.mark.parametrize(
    ("text", "worded"),
    [
        (
            "If the operator confirms it, give distrustedKeys sha256:ab@x.",
            "If the operator confirms it, give --distrusted-key sha256:ab@x.",
        ),
        (
            "distrustedKeys gives k the instant t",
            "--distrusted-key gives k the instant t",
        ),
        (
            f"if k leaked as well, add sha256:{'c' * 64} to distrustedKeys too.",
            f"if k leaked as well, add --distrusted-key sha256:{'c' * 64} too.",
        ),
        (
            "k is in distrustedKeys, and this closure still counts",
            "k is given as a --distrusted-key, and this closure still counts",
        ),
        (
            "If k is honest, pin sha256:e in trustAnchors (VAULT_TRUST_ANCHORS on the Server)",
            "If k is honest, pin sha256:e with --trust-anchor (VAULT_TRUST_ANCHORS on the Server)",
        ),
        (
            "No trustAnchors were given, so ... (sha256:<hex>) as trustAnchors.",
            "No --trust-anchor was given, so ... (sha256:<hex>) as --trust-anchor.",
        ),
        (
            "(requireKeyId, or requireSuppliedKeys refusing a key)",
            "(--require-key-id, or --require-supplied-keys refusing a key)",
        ),
        (
            "distrustedFrom and VAULT_DISTRUSTED_KEYS stay as they are",
            "distrustedFrom and VAULT_DISTRUSTED_KEYS stay as they are",
        ),
    ],
)
def test_the_report_names_flags_as_agledger_verify_words_them(
    text: str, worded: str
) -> None:
    """@agledger/verify's ``flagWording`` cases."""
    assert _flag_wording(text) == worded


def test_agledger_verify_keeps_the_tamper_advice_on_drift_the_listing_does_not_explain(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    stripped = _load()
    del stripped["exportMetadata"]["signingKeyWindows"][K[:16]]["distrustedFrom"]
    path = tmp_path / "export.json"
    path.write_text(json.dumps(stripped))
    code, out = _text(capsys, path)
    assert code == 1
    remedies = [line for line in out.splitlines() if line.strip().startswith("->")]
    assert len(remedies) == 2
    assert all(TAMPER in line for line in remedies)


def test_agledger_verify_rewords_prose_only_and_passes_a_data_field_that_spells_an_option_name_as_it_is(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    doc = _load()
    doc["exportMetadata"]["recordId"] = "distrustedKeys"
    doc["verificationGuide"] = {
        **doc.get("verificationGuide", {}),
        "unsignedFields": ["trustAnchors", "requireKeyId"],
    }
    path = tmp_path / "export.json"
    path.write_text(json.dumps(doc))
    assert run_cli([str(path), "--trust-anchor", F, "-f", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["recordId"] == "distrustedKeys"
    assert report["unsignedProjectionFields"] == ["trustAnchors", "requireKeyId"]
    assert f"give --distrusted-key sha256:{K}@{FROM}." in report["brokenAt"]["detail"]
    assert (
        f"give --distrusted-key sha256:{K}@{FROM}."
        in report["keyTrust"]["findings"][0]["detail"]
    )
    assert run_cli([str(path), "--trust-anchor", F]) == 1
    assert (
        "  record            : distrustedKeys" in capsys.readouterr().out.splitlines()
    )


def test_a_dump_report_rewords_failure_messages_and_details_never_ids_scopes_or_codes() -> (
    None
):
    finding = KeyRegistryFinding(
        "KEY_CLOSURE_INVALID",
        "trustAnchors",
        "distrustedKeys",
        "give distrustedKeys sha256:ab@x",
    )
    report = VerifyReport(
        ok=False,
        vault=VaultChainsReport(
            failures=[
                Failure(
                    "CHAIN_KEY_EXPIRED",
                    "the instant distrustedKeys gives",
                    scope_id="distrustedKeys",
                    signing_key_id="trustAnchors",
                )
            ],
            accounted=[
                AccountedEntry(
                    code="CHAIN_SIGNED_BY_DISTRUSTED_KEY",
                    chain="record",
                    record_id="distrustedKeys",
                    org_id="trustAnchors",
                    scope_id="requireKeyId",
                    position=0,
                    key_id="agentKeys",
                    detail="which distrustedKeys names",
                )
            ],
        ),
        org_admin_reads=TenantAdminReadsReport(
            failures=[
                Failure(
                    "TENANT_READ_KEY_UNANCHORED",
                    "pin it in trustAnchors",
                    scope_id="trustAnchors",
                )
            ]
        ),
        key_trust=KeyTrustReport(
            status="walked", detail="No trustAnchors were given", findings=[finding]
        ),
    )
    before = json.dumps(report.to_json())
    worded = _dump_report_with_flags(report).to_json()
    assert json.dumps(report.to_json()) == before
    assert worded["keyTrust"]["detail"] == "No --trust-anchor was given"
    assert worded["keyTrust"]["findings"][0] == {
        "code": "KEY_CLOSURE_INVALID",
        "keyId": "trustAnchors",
        "statementId": "distrustedKeys",
        "detail": "give --distrusted-key sha256:ab@x",
    }
    failure = worded["vault"]["failures"][0]
    assert (failure["message"], failure["scopeId"], failure["signingKeyId"]) == (
        "the instant --distrusted-key gives",
        "distrustedKeys",
        "trustAnchors",
    )
    accounted = worded["vault"]["accounted"][0]
    assert (
        accounted["detail"],
        accounted["recordId"],
        accounted["orgId"],
        accounted["scopeId"],
        accounted["keyId"],
    ) == (
        "which --distrusted-key names",
        "distrustedKeys",
        "trustAnchors",
        "requireKeyId",
        "agentKeys",
    )
    assert worded["orgAdminReads"]["failures"][0] == {
        **report.to_json()["orgAdminReads"]["failures"][0],
        "message": "pin it with --trust-anchor",
    }
