"""``a2a.call`` envelope and the /a2a HTTP 4xx error mapping."""

import json

import httpx
import pytest
import respx

from agledger import AgledgerClient, AsyncAgledgerClient
from agledger._errors import APIError

BASE = "https://agledger.example.com"

JSONRPC_ERROR = {
    "jsonrpc": "2.0",
    "id": None,
    "error": {
        "code": -32600,
        "message": "body/params must be object",
        "data": [
            {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "INVALID_REQUEST",
                "domain": "agledger.ai",
                "metadata": {
                    "detail": "params must be an object",
                    "recoveryHint": "Omit params or send an object.",
                    "requestId": "req-1",
                    "retryable": "false",
                },
            }
        ],
    },
}


@respx.mock
def test_call_without_params_omits_the_key():
    route = respx.post(f"{BASE}/a2a").mock(return_value=httpx.Response(200, json={"jsonrpc": "2.0"}))
    AgledgerClient(base_url=BASE, api_key="k").a2a.call("ListTasks")
    body = json.loads(route.calls[0].request.content)
    assert "params" not in body and body["method"] == "ListTasks"


@respx.mock
def test_call_with_params_sends_them_even_when_empty():
    route = respx.post(f"{BASE}/a2a").mock(return_value=httpx.Response(200, json={"jsonrpc": "2.0"}))
    AgledgerClient(base_url=BASE, api_key="k").a2a.call("ListTasks", {})
    assert json.loads(route.calls[0].request.content)["params"] == {}


@respx.mock
async def test_async_call_without_params_omits_the_key():
    route = respx.post(f"{BASE}/a2a").mock(return_value=httpx.Response(200, json={"jsonrpc": "2.0"}))
    async with AsyncAgledgerClient(base_url=BASE, api_key="k") as client:
        await client.a2a.call("ListTasks")
    assert "params" not in json.loads(route.calls[0].request.content)


@respx.mock
def test_http_4xx_jsonrpc_error_maps_the_error_info():
    respx.post(f"{BASE}/a2a").mock(return_value=httpx.Response(400, json=JSONRPC_ERROR))
    client = AgledgerClient(base_url=BASE, api_key="k")
    with pytest.raises(APIError) as excinfo:
        client.a2a.call("ListTasks", {"bogus": 1})
    err = excinfo.value
    assert err.code == "INVALID_REQUEST"
    assert err.detail == "params must be an object" and str(err) == err.detail
    assert err.recovery_hint == "Omit params or send an object."
    assert err.request_id == "req-1" and err.retryable is False
    assert err.details == JSONRPC_ERROR["error"]
    assert err.raw_body is not None and json.loads(err.raw_body) == JSONRPC_ERROR


@respx.mock
def test_jsonrpc_error_without_error_info_falls_back_to_the_rpc_code_and_message():
    body = {"jsonrpc": "2.0", "id": None, "error": {"code": -32601, "message": "Method not found"}}
    respx.post(f"{BASE}/a2a").mock(return_value=httpx.Response(400, json=body))
    client = AgledgerClient(base_url=BASE, api_key="k")
    with pytest.raises(APIError) as excinfo:
        client.a2a.call("Nope")
    assert excinfo.value.code == "-32601"
    assert excinfo.value.detail == "Method not found"
    assert excinfo.value.recovery_hint is None


@respx.mock
def test_a_rest_problem_body_is_unchanged():
    respx.get(f"{BASE}/v1/records/x").mock(
        return_value=httpx.Response(404, json={"error": "NOT_FOUND", "detail": "no such record"})
    )
    client = AgledgerClient(base_url=BASE, api_key="k")
    with pytest.raises(APIError) as excinfo:
        client.records.get("x")
    assert excinfo.value.code == "NOT_FOUND" and excinfo.value.raw_body is None


@respx.mock
def test_cancel_task_puts_the_reason_under_the_one_metadata_key():
    route = respx.post(f"{BASE}/a2a").mock(return_value=httpx.Response(200, json={"jsonrpc": "2.0"}))
    AgledgerClient(base_url=BASE, api_key="k").a2a.cancel_task(
        task_id="0199a8f0-0000-7000-8000-000000000001", reason="superseded"
    )
    sent = json.loads(route.calls.last.request.content)
    assert sent["method"] == "CancelTask"
    assert sent["params"] == {
        "id": "0199a8f0-0000-7000-8000-000000000001",
        "metadata": {"agledger:reason": "superseded"},
    }


@respx.mock
def test_cancel_task_without_a_reason_sends_no_metadata_key():
    route = respx.post(f"{BASE}/a2a").mock(return_value=httpx.Response(200, json={"jsonrpc": "2.0"}))
    AgledgerClient(base_url=BASE, api_key="k").a2a.cancel_task(name="tasks/0199a8f0-0000-7000-8000-000000000001")
    sent = json.loads(route.calls.last.request.content)
    assert sent["params"] == {"name": "tasks/0199a8f0-0000-7000-8000-000000000001"}


def test_cancel_task_takes_exactly_one_task_name():
    client = AgledgerClient(base_url=BASE, api_key="k")
    with pytest.raises(ValueError):
        client.a2a.cancel_task(reason="x")
    with pytest.raises(ValueError):
        client.a2a.cancel_task(name="tasks/a", task_id="a")
