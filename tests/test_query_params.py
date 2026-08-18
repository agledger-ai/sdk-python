"""Query-parameter serialization.

``httpx`` renders a dict parameter as its Python repr, so
``search(metadata={"state": "blocked"})`` went out as
``metadata={'state': 'blocked'}`` and the engine answered 400. Metadata-filtered
search had therefore never worked from this SDK, and the same defect would have
swallowed the ``criteria`` filter. These pin the bracket notation the API
documents, plus the datetime and pruning rules around it.
"""

from datetime import datetime, timezone
from urllib.parse import unquote

import httpx
import respx

from agledger import AgledgerClient
from agledger._http import _query_params

BASE = "https://agledger.example.com"
PAGE = {"data": [], "hasMore": False}


def _client() -> AgledgerClient:
    return AgledgerClient(base_url=BASE, api_key="test-key")


@respx.mock
def test_mapping_params_use_bracket_notation():
    route = respx.get(f"{BASE}/v1/records/search").mock(return_value=httpx.Response(200, json=PAGE))
    _client().records.search(metadata={"state": "blocked", "retries": 3}, criteria={"amount": "750"})

    url = unquote(str(route.calls.last.request.url))
    assert "metadata[state]=blocked" in url
    assert "metadata[retries]=3" in url
    assert "criteria[amount]=750" in url
    assert "{" not in url  # the Python repr never reaches the wire


@respx.mock
def test_none_members_of_a_mapping_are_dropped():
    route = respx.get(f"{BASE}/v1/records/search").mock(return_value=httpx.Response(200, json=PAGE))
    _client().records.search(metadata={"keep": "yes", "gone": None})

    url = unquote(str(route.calls.last.request.url))
    assert "metadata[keep]=yes" in url
    assert "gone" not in url


def test_datetime_is_iso_8601_not_str():
    # The typed methods declare `str` for date params, so this covers the
    # untyped paths: `client.request()` and any mapping passed straight through.
    # `str(datetime)` uses a space separator, which the date-time params reject.
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    out = _query_params({"from": when, "metadata": {"at": when}})
    assert out["from"] == "2026-01-02T03:04:05+00:00"
    assert out["metadata[at]"] == "2026-01-02T03:04:05+00:00"


def test_none_values_are_dropped_entirely():
    assert _query_params({"a": None, "b": 0, "c": False}) == {"b": 0, "c": False}


@respx.mock
def test_ref_filters_stay_flat_dotted_keys():
    route = respx.get(f"{BASE}/v1/records/search").mock(return_value=httpx.Response(200, json=PAGE))
    _client().records.search(ref_system="jira", ref_type="issue", ref_id="ABC-1")

    url = unquote(str(route.calls.last.request.url))
    assert "ref.system=jira" in url
    assert "ref.type=issue" in url
    assert "ref.id=ABC-1" in url


@respx.mock
def test_supersession_filters_reach_the_wire():
    route = respx.get(f"{BASE}/v1/records/search").mock(return_value=httpx.Response(200, json=PAGE))
    _client().records.search(superseded=False, supersedes_record_id="rec-1")

    url = unquote(str(route.calls.last.request.url))
    assert "superseded=false" in url
    assert "supersedesRecordId=rec-1" in url


@respx.mock
def test_conformance_parses_a_real_capabilities_payload():
    """`capabilities` values are not all booleans.

    `signingAlgorithms` is a list, so the old `dict[str, bool]` annotation
    rejected every real response. Nothing caught it because no method returned
    the model. `limits` rides on the same response.
    """
    respx.get(f"{BASE}/v1/conformance").mock(
        return_value=httpx.Response(
            200,
            json={
                "version": "1.4.0",
                "contractTypes": 4,
                "capabilities": {
                    "recordLifecycle": True,
                    "signingAlgorithms": ["Ed25519", "ES256"],
                },
                "limits": {"metadataMaxProperties": 50, "recordBodyMaxBytes": 1048576},
            },
        )
    )
    report = _client().discovery.get_conformance()

    assert report.version == "1.4.0"
    assert (report.capabilities or {})["signingAlgorithms"] == ["Ed25519", "ES256"]
    assert (report.limits or {})["metadataMaxProperties"] == 50
