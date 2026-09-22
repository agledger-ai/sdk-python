"""Actor attribution is signature-covered, so it is verified, not displayed on trust.

The Python mirror of verify-core's ``actor-attribution.test.ts`` and
``@agledger/verify``'s ``actor-attribution.test.ts``, on the same unmodified
live 1.8.0 fixtures: the export's guide names ``actorDisplayName``,
``actorOwnerType`` and ``humanReadableLabel`` as unsigned display projections
and tells the auditor that attribution IS the ``actorId``/``actorOwnerId``
UUID. Those, plus ``actorRole``, ride in the COSE protected header at
CWT_Claims label 15 -> private label -65539. Before this check an export could
be re-attributed to another actor and still verify, which made the guide's own
advice unverifiable.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

from agledger.verify import load_dump, verify_dump, verify_export
from agledger.verify.verify_export import (  # pyright: ignore[reportPrivateUsage]
    _decode_cose_sign1,
    _extract_actor_claim,
)

LIVE = Path(__file__).parent / "fixtures" / "live-1.8.0"
EXPORT = LIVE / "export-lifecycle.json"
DUMP = str(LIVE / "dump")


def _export() -> dict[str, Any]:
    return json.loads(EXPORT.read_text())


def test_the_signed_actor_claim_equals_the_row_columns_on_real_engine_output():
    doc = _export()
    for entry in doc["entries"]:
        parts = _decode_cose_sign1(base64.b64decode(entry["integrity"]["coseSign1"]))
        assert parts is not None
        claim = _extract_actor_claim(parts[0])
        assert claim is not None
        key_id, role, owner_id = claim
        assert key_id == entry["actorId"]
        assert role == entry["actorRole"]
        assert owner_id == entry["actorOwnerId"]


def test_a_clean_export_passes_and_reports_the_check_as_applied():
    result = verify_export(_export())
    assert result.valid is True
    assert result.optional_checks["actor_attribution"] == "applied"


def test_an_export_re_attributed_to_another_owner_is_refused():
    doc = _export()
    original = doc["entries"][0]["actorOwnerId"]
    doc["entries"][0]["actorOwnerId"] = "00000000-0000-7000-8000-000000000000"
    assert doc["entries"][0]["actorOwnerId"] != original

    result = verify_export(doc)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.code == "CHAIN_ACTOR_ATTRIBUTION_MISMATCH"
    assert "actorOwnerId" in (result.broken_at.detail or "")


def test_a_rewritten_actor_id_or_role_is_refused():
    for field, value in (
        ("actorId", "00000000-0000-7000-8000-000000000001"),
        ("actorRole", "platform"),
    ):
        doc = _export()
        doc["entries"][0][field] = value
        result = verify_export(doc)
        assert result.valid is False
        assert result.broken_at is not None
        assert result.broken_at.code == "CHAIN_ACTOR_ATTRIBUTION_MISMATCH"
        assert field in (result.broken_at.detail or "")


def test_a_re_attribution_at_a_later_position_is_caught_too():
    doc = _export()
    assert len(doc["entries"]) > 2
    doc["entries"][2]["actorOwnerId"] = "00000000-0000-7000-8000-000000000002"
    result = verify_export(doc)
    assert result.valid is False
    assert result.broken_at is not None
    assert result.broken_at.position == 3


def test_an_artifact_without_the_actor_columns_skips_rather_than_fails():
    doc = _export()
    for entry in doc["entries"]:
        for field in ("actorId", "actorRole", "actorOwnerId"):
            entry.pop(field, None)
    result = verify_export(doc)
    assert result.valid is True
    assert result.optional_checks["actor_attribution"] == "skipped_no_input"


def test_the_dump_path_refuses_a_re_attributed_row(tmp_path: Any):
    dump = load_dump(DUMP)
    clean = verify_dump(dump)
    assert clean.ok is True
    assert clean.vault.optional_checks["actor_attribution"] == "applied"

    tampered = copy.deepcopy(dump)
    tampered.vault_entries[0]["actor_owner_id"] = "00000000-0000-7000-8000-000000000000"
    report = verify_dump(tampered)
    assert report.ok is False
    assert "CHAIN_ACTOR_ATTRIBUTION_MISMATCH" in [f.code for f in report.vault.failures]
