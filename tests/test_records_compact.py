"""``view="compact"`` on the record reads.

Under ``?view=compact`` the Server leaves out every top-level field whose value
is null and trims each ``nextSteps`` entry to ``action``, ``method`` and
``href``, on the row and on the list envelope alike. The full ``NextStep``
requires ``description``, so reading a compact body into ``RecordRow`` raised a
ValidationError on the first record that had a next step. The compact reads
therefore return their own types, and the overloads say which one a call gets.
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

from agledger import (
    AgledgerClient,
    AsyncAgledgerClient,
    NextStepCompact,
    RecordRow,
    RecordRowCompact,
    RecordRowCompactPage,
)
from agledger.types import Page

BASE = "https://agledger.example.com"
RID = "11111111-1111-4111-8111-111111111111"

COMPACT_ROW: dict[str, Any] = {
    "id": RID,
    "orgId": "22222222-2222-4222-8222-222222222222",
    "principalAgentId": "33333333-3333-4333-8333-333333333333",
    "type": "notarize-generic-v1",
    "platform": "api",
    "status": "ACTIVE",
    "criteria": {"note": None},
    "submissionCount": 0,
    "version": 1,
    "createdAt": "2026-09-28T00:00:00.000Z",
    "updatedAt": "2026-09-28T00:00:00.000Z",
    "nextSteps": [{"action": "submit-completion", "method": "POST", "href": f"/v1/records/{RID}/completions"}],
}
COMPACT_PAGE: dict[str, Any] = {
    "data": [COMPACT_ROW],
    "hasMore": False,
    "nextCursor": None,
    "total": 1,
    "limit": 50,
    "offset": 0,
    "nextSteps": [{"action": "create", "method": "POST", "href": "/v1/records"}],
}


def test_a_compact_body_does_not_parse_as_a_full_record() -> None:
    """Why the compact reads cannot share the full type."""
    with pytest.raises(ValueError, match="description"):
        RecordRow.model_validate(COMPACT_ROW)


@respx.mock
def test_get_compact_sends_the_view_and_returns_a_compact_row() -> None:
    route = respx.get(f"{BASE}/v1/records/{RID}").mock(return_value=httpx.Response(200, json=COMPACT_ROW))
    with AgledgerClient(api_key="agl_agt_test", base_url=BASE) as client:
        row = client.records.get(RID, view="compact")
    assert route.calls[0].request.url.params["view"] == "compact"
    assert isinstance(row, RecordRowCompact)
    # An absent field was null on the Server; it reads as None here.
    assert row.performer_agent_id is None
    assert row.next_steps is not None
    assert isinstance(row.next_steps[0], NextStepCompact)
    assert row.next_steps[0].href == f"/v1/records/{RID}/completions"


@respx.mock
def test_get_without_a_view_sends_none_and_returns_a_full_row() -> None:
    full = dict(COMPACT_ROW, nextSteps=[dict(COMPACT_ROW["nextSteps"][0], description="Deliver it.")])
    route = respx.get(f"{BASE}/v1/records/{RID}").mock(return_value=httpx.Response(200, json=full))
    with AgledgerClient(api_key="agl_agt_test", base_url=BASE) as client:
        row = client.records.get(RID)
        client.records.get(RID, view="full", integrity=True)
    assert "view" not in route.calls[0].request.url.params
    assert dict(route.calls[1].request.url.params) == {"view": "full", "integrity": "true"}
    assert type(row) is RecordRow


@respx.mock
def test_list_and_search_compact_return_a_compact_page() -> None:
    listing = respx.get(f"{BASE}/v1/records").mock(return_value=httpx.Response(200, json=COMPACT_PAGE))
    search = respx.get(f"{BASE}/v1/records/search").mock(return_value=httpx.Response(200, json=COMPACT_PAGE))
    with AgledgerClient(api_key="agl_agt_test", base_url=BASE) as client:
        page = client.records.list(view="compact", limit=10)
        found = client.records.search(view="compact", status="ACTIVE")
    assert dict(listing.calls[0].request.url.params) == {"view": "compact", "limit": "10"}
    assert search.calls[0].request.url.params["view"] == "compact"
    for p in (page, found):
        assert isinstance(p, RecordRowCompactPage)
        assert isinstance(p.data[0], RecordRowCompact)
        assert (p.limit, p.has_more) == (50, False)
        assert "offset" not in type(p).model_fields
        assert p.next_steps is not None
        assert isinstance(p.next_steps[0], NextStepCompact)


@respx.mock
def test_list_without_a_view_is_still_a_full_page() -> None:
    full = {"data": [], "hasMore": False, "nextCursor": None, "total": 0}
    respx.get(f"{BASE}/v1/records").mock(return_value=httpx.Response(200, json=full))
    with AgledgerClient(api_key="agl_agt_test", base_url=BASE) as client:
        page = client.records.list()
    assert type(page) is Page[RecordRow]


@respx.mock
def test_list_all_compact_sends_the_view_and_yields_compact_rows() -> None:
    route = respx.get(f"{BASE}/v1/records").mock(return_value=httpx.Response(200, json=COMPACT_PAGE))
    with AgledgerClient(api_key="agl_agt_test", base_url=BASE) as client:
        rows = list(client.records.list_all(view="compact", limit=10))
    assert route.calls[0].request.url.params["view"] == "compact"
    assert route.calls[0].request.url.params["limit"] == "10"
    assert len(rows) == 1
    assert isinstance(rows[0], RecordRowCompact)
    assert rows[0].next_steps is not None
    assert isinstance(rows[0].next_steps[0], NextStepCompact)


@respx.mock
def test_list_all_without_a_view_sends_none_and_yields_full_rows() -> None:
    full_row = {**COMPACT_ROW, "nextSteps": []}
    full = {"data": [full_row], "hasMore": False, "nextCursor": None, "total": 1}
    route = respx.get(f"{BASE}/v1/records").mock(return_value=httpx.Response(200, json=full))
    with AgledgerClient(api_key="agl_agt_test", base_url=BASE) as client:
        rows = list(client.records.list_all())
    assert "view" not in route.calls[0].request.url.params
    assert type(rows[0]) is RecordRow


@respx.mock
async def test_async_compact_reads_match_sync() -> None:
    get = respx.get(f"{BASE}/v1/records/{RID}").mock(return_value=httpx.Response(200, json=COMPACT_ROW))
    respx.get(f"{BASE}/v1/records").mock(return_value=httpx.Response(200, json=COMPACT_PAGE))
    respx.get(f"{BASE}/v1/records/search").mock(return_value=httpx.Response(200, json=COMPACT_PAGE))
    async with AsyncAgledgerClient(api_key="agl_agt_test", base_url=BASE) as client:
        row = await client.records.get(RID, view="compact")
        page = await client.records.list(view="compact", cursor="c1")
        found = await client.records.search(view="compact")
        rows = [r async for r in client.records.list_all(view="compact")]
    assert get.calls[0].request.url.params["view"] == "compact"
    assert isinstance(rows[0], RecordRowCompact)
    assert isinstance(row, RecordRowCompact)
    assert isinstance(page, RecordRowCompactPage)
    assert isinstance(found, RecordRowCompactPage)


_TYPED_CALLER = """
from collections.abc import AsyncIterator, Iterator
from typing import assert_type

from agledger import (
    AgledgerClient, AsyncAgledgerClient, RecordRow, RecordRowCompact, RecordRowCompactPage,
)
from agledger.types import Page


def sync_reads(client: AgledgerClient) -> None:
    assert_type(client.records.get("r"), RecordRow)
    assert_type(client.records.get("r", view="full"), RecordRow)
    assert_type(client.records.get("r", view="compact"), RecordRowCompact)
    assert_type(client.records.list(), Page[RecordRow])
    assert_type(client.records.list(view="compact"), RecordRowCompactPage)
    assert_type(client.records.search(view="compact"), RecordRowCompactPage)
    assert_type(client.records.search(), Page[RecordRow])
    assert_type(client.records.list_all(), Iterator[RecordRow])
    assert_type(client.records.list_all(view="compact"), Iterator[RecordRowCompact])


async def async_reads(client: AsyncAgledgerClient) -> None:
    assert_type(await client.records.get("r"), RecordRow)
    assert_type(await client.records.get("r", view="compact"), RecordRowCompact)
    assert_type(await client.records.list(view="compact"), RecordRowCompactPage)
    assert_type(await client.records.search(view="full"), Page[RecordRow])
    assert_type(client.records.list_all(view="compact"), AsyncIterator[RecordRowCompact])
    assert_type(client.records.list_all(), AsyncIterator[RecordRow])
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


def test_the_overloads_give_each_view_its_own_static_type(tmp_path: Path) -> None:
    """``assert_type`` erases to nothing at runtime, so it is compiled here.
    The second probe is known false and must fail, which proves the check can."""
    ok = _pyright(tmp_path, _TYPED_CALLER)
    assert ok.returncode == 0, ok.stdout
    wrong = _pyright(
        tmp_path,
        _TYPED_CALLER.replace(
            'assert_type(client.records.get("r", view="compact"), RecordRowCompact)',
            'assert_type(client.records.get("r", view="compact"), RecordRow)',
        ),
    )
    assert wrong.returncode != 0
    assert "assert_type" in wrong.stdout
