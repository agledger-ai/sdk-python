"""The vault scan job and the trusted issuer are typed as the wire dict.

``admin.vault.scan.status()`` and ``admin.trusted_issuers.get()`` / ``create()``
/ ``update()`` returned ``dict[str, Any]``, so the break reasons, the
first-finding reason and the issuer's allowed algorithms were names nothing
checked. They return ``TypedDict``s keyed by the wire names now: the value is
still the dict the Server sent, so subscripting code keeps working, and a
static checker sees the enums the parity snapshot pins.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from agledger import AgledgerClient

BASE = "https://agledger.example.com"
JOB = "44444444-4444-4444-8444-444444444444"
ISSUER = "55555555-5555-4555-8555-555555555555"

SCAN_JOB: dict[str, Any] = {
    "jobId": JOB,
    "state": "completed",
    "startedAt": "2026-09-28T00:00:00.000Z",
    "completedAt": "2026-09-28T00:00:01.000Z",
    "result": {
        "recordsScanned": 2,
        "verified": 1,
        "broken": 1,
        "signatureErrors": 0,
        "healthy": False,
        "recordsMissingChain": 0,
        "missingChainRecords": [],
        "brokenRecords": [
            {
                "recordId": "66666666-6666-4666-8666-666666666666",
                "brokenAt": 4,
                "reason": "payload_drift",
                "firstFinding": {"brokenAt": 2, "reason": "key_expired"},
            }
        ],
        "brokenRecordsTruncated": False,
        "globalChains": {
            "total": 1,
            "verified": 1,
            "broken": 0,
            "signatureErrors": 0,
            "brokenChains": [],
            "brokenChainsTruncated": False,
        },
        "orgAdminReads": {"orgs": 1, "broken": 1, "brokenOrgs": [{"orgId": "o", "reason": "leaf_signature_missing", "at": 0}]},
        "scannedAt": "2026-09-28T00:00:01.000Z",
    },
}


@respx.mock
def test_scan_status_returns_the_wire_dict() -> None:
    respx.get(f"{BASE}/v1/admin/vault/scan/{JOB}").mock(return_value=httpx.Response(200, json=SCAN_JOB))
    with AgledgerClient(api_key="agl_adm_test", base_url=BASE) as client:
        job = client.admin.vault.scan.status(JOB)
    assert job == SCAN_JOB
    result = job.get("result")
    assert result is not None
    assert result["brokenRecords"][0]["reason"] == "payload_drift"


@respx.mock
def test_create_sends_allowed_algs_and_applies_to() -> None:
    route = respx.post(f"{BASE}/v1/admin/trusted-issuers").mock(
        return_value=httpx.Response(201, json={"id": ISSUER, "allowedAlgs": ["ES256"]})
    )
    with AgledgerClient(api_key="agl_adm_test", base_url=BASE) as client:
        issuer = client.admin.trusted_issuers.create(
            issuer_url="https://idp.example.com",
            expected_audience="agledger",
            applies_to="agent",
            allowed_algs=["ES256", "EdDSA"],
        )
    sent = route.calls[0].request.read()
    assert b'"allowedAlgs":["ES256","EdDSA"]' in sent.replace(b" ", b"")
    assert b'"appliesTo":"agent"' in sent.replace(b" ", b"")
    assert issuer["id"] == ISSUER


_TYPED_CALLER = """
from typing import assert_type

from agledger import (
    AgledgerClient,
    OrgReadsBreakReason,
    TrustedIssuerAlg,
    VaultScanBreakReason,
    VaultScanFirstFindingReason,
    VaultScanState,
)


def reads(client: AgledgerClient) -> None:
    job = client.admin.vault.scan.status("j")
    assert_type(job["state"], VaultScanState)
    result = job.get("result")
    if result is None:
        return
    row = result["brokenRecords"][0]
    assert_type(row["reason"], VaultScanBreakReason)
    finding = row.get("firstFinding")
    if finding is not None:
        assert_type(finding["reason"], VaultScanFirstFindingReason)
    chains = result.get("globalChains")
    if chains is not None:
        assert_type(chains["brokenChains"][0]["reason"], VaultScanBreakReason)
    reads_log = result.get("orgAdminReads")
    if reads_log is not None:
        for org in reads_log.get("brokenOrgs", []):
            assert_type(org["reason"], OrgReadsBreakReason)
    issuer = client.admin.trusted_issuers.get("i")
    assert_type(issuer["allowedAlgs"], list[TrustedIssuerAlg] | None)
    client.admin.trusted_issuers.create(
        issuer_url="u", expected_audience="a", allowed_algs=["ES256"]
    )
"""


def _pyright(tmp_path: Path, source: str) -> subprocess.CompletedProcess[str]:
    exe = shutil.which("pyright") or str(Path(sys.executable).parent / "pyright")
    if not Path(exe).exists():
        pytest.skip("pyright is not installed")
    probe = tmp_path / "probe.py"
    probe.write_text(textwrap.dedent(source))
    src = Path(__file__).resolve().parent.parent / "src"
    config = tmp_path / "pyrightconfig.json"
    config.write_text(f'{{"extraPaths": ["{src}"], "typeCheckingMode": "strict"}}')
    return subprocess.run(
        [exe, "--project", str(config), str(probe)], capture_output=True, text=True, check=False
    )


def test_the_reads_carry_the_pinned_enums(tmp_path: Path) -> None:
    """``assert_type`` erases to nothing at runtime, so it is compiled here.
    The second probe sends an algorithm the Server refuses and must fail,
    which proves the closed ``TrustedIssuerAlg`` is what the parameter takes."""
    ok = _pyright(tmp_path, _TYPED_CALLER)
    assert ok.returncode == 0, ok.stdout
    wrong = _pyright(tmp_path, _TYPED_CALLER.replace('allowed_algs=["ES256"]', 'allowed_algs=["HS256"]'))
    assert wrong.returncode != 0
    assert "HS256" in wrong.stdout
