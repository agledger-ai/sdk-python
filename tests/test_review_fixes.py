"""Regressions from an independent review of the OIDC credential, the HTTP
client's 401 handling and the offline verifier. Each test failed before its
fix."""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

import agledger._oidc as oidc_module
from agledger import (
    AgledgerClient,
    AsyncAgledgerClient,
    AuthenticationError,
    ConfigurationError,
    CredentialContext,
    OidcCertExchangeError,
    async_oidc_cert_credential,
    oidc_cert_credential,
)
from agledger.verify import verify_export
from agledger.verify.cli import run_cli

BASE = "https://agledger.example.com"
EXCHANGE = f"{BASE}/v1/auth/oidc/cert"
ME = f"{BASE}/v1/auth/me"
RECORDS = f"{BASE}/v1/records"
LIVE = Path(__file__).parent / "fixtures" / "live-1.8.0"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Idp:
    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            self.calls += 1
            n = self.calls
        header = _b64url(json.dumps({"alg": "RS256"}).encode())
        payload = _b64url(json.dumps({"sub": "w", "jti": f"j{n}"}).encode())
        return f"{header}.{payload}.{_b64url(b's')}"


def _cert(n: int, *, issued: str = "2026-09-18T00:00:00.000Z", expires: str = "2026-09-18T00:02:00.000Z") -> httpx.Response:
    return httpx.Response(201, json={
        "cert": {"id": f"c{n}", "issuedAt": issued, "expiresAt": expires},
        "certJws": f"cert-jws-{n}",
        "nextSteps": [],
    })


class Exchanges:
    def __init__(self, *responses: httpx.Response | Exception) -> None:
        self.queue = list(responses)
        self.count = 0
        self._lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.count += 1
            item = self.queue.pop(0) if len(self.queue) > 1 else self.queue[0]
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [1000.0]
    monkeypatch.setattr(oidc_module, "_monotonic", lambda: now[0])
    return now


def _client(**kw: Any) -> AgledgerClient:
    return AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=kw.pop("idp", Idp()), **kw), base_url=BASE)


# --- 1: only a 401 about the cert forces a re-exchange ---

DELEGATION_401 = httpx.Response(401, json={
    "message": "AGLedger-On-Behalf-Of: token expired", "code": "UNAUTHORIZED", "reason": "expired",
})


@respx.mock
def test_a_delegation_401_surfaces_without_a_re_exchange():
    exchange = respx.post(EXCHANGE).mock(side_effect=Exchanges(_cert(1), _cert(2)))
    respx.post(RECORDS).mock(return_value=DELEGATION_401)
    probe = respx.get(ME).mock(return_value=httpx.Response(200, json={"authType": "ephemeral_cert"}))
    with pytest.raises(AuthenticationError) as info:
        _client().records.create(type="t", criteria={"summary": "s"}, on_behalf_of="delegation.jwt.x")
    assert "On-Behalf-Of" in str(info.value)
    assert exchange.call_count == 1, "the cert was fine; the delegation token was not"
    assert probe.call_count == 1


@respx.mock
def test_a_signature_401_surfaces_without_a_re_exchange():
    exchange = respx.post(EXCHANGE).mock(side_effect=Exchanges(_cert(1), _cert(2)))
    create = respx.post(RECORDS).mock(return_value=httpx.Response(401, json={
        "message": "X-Agent-Signature does not verify against the ephemeral cert public key",
    }))
    respx.get(ME).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(AuthenticationError):
        _client().records.create(type="t", criteria={"summary": "s"})
    assert exchange.call_count == 1
    assert create.call_count == 1


@respx.mock
def test_a_cert_401_still_re_exchanges_and_retries():
    exchange = respx.post(EXCHANGE).mock(side_effect=Exchanges(_cert(1), _cert(2)))
    create = respx.post(RECORDS).mock(side_effect=[
        httpx.Response(401, json={"message": "Ephemeral cert expired; mint a fresh one"}),
        httpx.Response(201, json={"id": "r"}),
    ])
    respx.get(ME).mock(return_value=httpx.Response(401, json={"message": "Ephemeral cert expired"}))
    _client().request("POST", "/v1/records", json={"a": 1})
    assert exchange.call_count == 2
    assert create.calls.last.request.headers["authorization"] == "Bearer cert-jws-2"


# --- 2: a failed scheduled refresh keeps a cert that is still valid ---


@pytest.mark.parametrize(
    "failure",
    [
        httpx.Response(503, json={"message": "down"}),
        httpx.Response(429, json={"message": "slow down"}),
        httpx.Response(409, json={"message": "already exchanged"}),
        httpx.ConnectError("idp unreachable"),
    ],
    ids=["503", "429", "409", "connect"],
)
@respx.mock
def test_a_failed_refresh_keeps_the_valid_cert(failure: Any, clock: list[float]):
    exchange = respx.post(EXCHANGE).mock(side_effect=Exchanges(_cert(1), failure))
    me = respx.get(ME).mock(return_value=httpx.Response(200, json={}))
    client = _client()
    client.request("GET", "/v1/auth/me")
    clock[0] += 70  # past the refresh point, inside the 120s lifetime
    client.request("GET", "/v1/auth/me")
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-1"
    tried = exchange.call_count
    client.request("GET", "/v1/auth/me")  # asked again only after a recheck delay
    assert exchange.call_count == tried


@respx.mock
def test_a_token_source_that_raises_at_refresh_keeps_the_valid_cert(clock: list[float]):
    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("idp down")
        return Idp()()

    respx.post(EXCHANGE).mock(side_effect=Exchanges(_cert(1)))
    me = respx.get(ME).mock(return_value=httpx.Response(200, json={}))
    client = _client(idp=flaky)
    client.request("GET", "/v1/auth/me")
    clock[0] += 70
    client.request("GET", "/v1/auth/me")
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-1"


@respx.mock
def test_a_failed_exchange_after_expiry_raises(clock: list[float]):
    respx.post(EXCHANGE).mock(side_effect=Exchanges(_cert(1), httpx.Response(503, json={"message": "down"})))
    respx.get(ME).mock(return_value=httpx.Response(200, json={}))
    client = _client()
    client.request("GET", "/v1/auth/me")
    clock[0] += 121
    with pytest.raises(OidcCertExchangeError):
        client.request("GET", "/v1/auth/me")


@respx.mock
def test_the_lifetime_is_timed_from_local_receipt(clock: list[float]):
    # An exchange that takes 50s of a 120s cert: the refresh point is 60s after
    # the cert ARRIVED, not after the request left.
    exchanges = {"n": 0}

    def slow(request: httpx.Request) -> httpx.Response:
        exchanges["n"] += 1
        if exchanges["n"] == 1:
            clock[0] += 50
        return _cert(exchanges["n"])

    respx.post(EXCHANGE).mock(side_effect=slow)
    respx.get(ME).mock(return_value=httpx.Response(200, json={}))
    client = _client()
    client.request("GET", "/v1/auth/me")
    clock[0] += 30
    client.request("GET", "/v1/auth/me")
    assert exchanges["n"] == 1


# --- 3: no token, cert or key in a message or repr ---


def test_a_bad_function_bearer_does_not_leak_the_value():
    secret = b"secret-bearer-value"
    with pytest.raises(ConfigurationError) as info:
        AgledgerClient(bearer_token=lambda: secret, base_url=BASE).request("GET", "/v1/auth/me")  # type: ignore[arg-type,return-value]
    assert "secret-bearer-value" not in str(info.value)
    assert "bytes" in str(info.value)


def test_no_repr_carries_a_cert_or_token():
    cert = oidc_module._Cert(cert_jws="cert-jws-secret", cert={}, refresh_at=0, expires_at=0)  # pyright: ignore[reportPrivateUsage]
    assert "cert-jws-secret" not in repr(cert)
    context = CredentialContext(BASE, httpx.Client(), True, "rejected-cert-secret")
    assert "rejected-cert-secret" not in repr(context)


# --- 5: waiters share one failed exchange; an undatable cert is refused ---


@respx.mock
def test_waiting_threads_share_one_failed_exchange():
    gate = threading.Event()

    def refuse(request: httpx.Request) -> httpx.Response:
        gate.wait(2)
        return httpx.Response(503, json={"message": "down"})

    exchange = respx.post(EXCHANGE).mock(side_effect=refuse)
    respx.get(ME).mock(return_value=httpx.Response(200, json={}))
    client = _client()
    errors: list[BaseException] = []

    def run() -> None:
        try:
            client.request("GET", "/v1/auth/me")
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(6)]
    for t in threads:
        t.start()
    time.sleep(0.1)
    gate.set()
    for t in threads:
        t.join(5)
    assert exchange.call_count == 1
    assert len(errors) == 6 and all(isinstance(e, OidcCertExchangeError) for e in errors)


@respx.mock
async def test_waiting_tasks_share_one_failed_exchange():
    async def refuse(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return httpx.Response(503, json={"message": "down"})

    exchange = respx.post(EXCHANGE).mock(side_effect=refuse)
    async with AsyncAgledgerClient(bearer_token=async_oidc_cert_credential(get_oidc_token=Idp()), base_url=BASE) as client:
        results = await asyncio.gather(*(client.request("GET", "/v1/auth/me") for _ in range(6)), return_exceptions=True)
    assert exchange.call_count == 1
    assert all(isinstance(r, OidcCertExchangeError) for r in results)


@respx.mock
def test_a_cert_without_a_parseable_validity_window_is_refused():
    respx.post(EXCHANGE).mock(return_value=_cert(1, issued="not a date"))
    me = respx.get(ME).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(OidcCertExchangeError, match="validity window"):
        _client().request("GET", "/v1/auth/me")
    assert me.call_count == 0


# --- 4: a runtime that refuses Ed25519 is reported per entry, not raised ---


def test_agent_keys_on_a_runtime_that_refuses_ed25519(monkeypatch: pytest.MonkeyPatch):
    import importlib

    # The package re-exports a function under the submodule's name.
    verify_export_module = importlib.import_module("agledger.verify.verify_export")
    key = json.loads((LIVE / "agent-cert-key.json").read_text())["publicKeyJwk"]

    def refuse(_raw: bytes) -> Any:
        raise ValueError("unsupported by the FIPS provider")

    monkeypatch.setattr(verify_export_module._Ed25519PublicKey, "from_public_bytes", staticmethod(refuse))  # pyright: ignore[reportPrivateUsage]
    real = verify_export_module.runtime_can_compute
    monkeypatch.setattr(verify_export_module, "runtime_can_compute", lambda alg: False if alg == "Ed25519" else real(alg))
    doc = json.loads((LIVE / "export-cert-lifecycle.json").read_text())
    result = verify_export(doc, public_keys={}, agent_keys=[key])
    assert not result.valid
    assert result.broken_at is not None and result.broken_at.code == "CHAIN_UNSUPPORTED_ALGORITHM"


# --- 6: strict equality, and a non-object row on_behalf_of is ignored ---


def _first_obo(doc: dict[str, Any]) -> dict[str, Any]:
    return next(e["payload"] for e in doc["entries"] if (e.get("payload") or {}).get("on_behalf_of"))


def test_a_boolean_rewritten_as_one_fails_the_binding():
    doc = json.loads((LIVE / "export-cert-lifecycle.json").read_text())
    obo = _first_obo(doc)["on_behalf_of"]
    assert obo["validated"] is True
    obo["validated"] = 1  # True == 1 in Python; not in the signed CBOR
    result = verify_export(doc)
    assert not result.valid
    assert result.broken_at is not None and result.broken_at.code == "CHAIN_PAYLOAD_BINDING_MISMATCH"


def test_a_row_on_behalf_of_that_is_not_an_object_is_ignored():
    doc = json.loads((LIVE / "export-cert-lifecycle.json").read_text())
    _first_obo(doc)["on_behalf_of"] = "an older row shape"
    assert verify_export(doc).valid


# --- 7: the CLI does not tell a caller who passed keys to pass keys ---


def test_cli_with_keys_that_match_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keys = tmp_path / "k.json"
    keys.write_text(json.dumps({"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}))
    run_cli([str(LIVE / "export-cert-lifecycle.json"), "--agent-keys", str(keys)])
    out = capsys.readouterr().out
    assert "pass --agent-keys" not in out
    assert "present=6 verified=0" in out
    assert "no supplied key" in out


def test_a_webhook_repr_does_not_print_its_signing_secret():
    from agledger import Webhook

    hook = Webhook.model_validate({
        "id": "wh", "url": "https://h.example", "isActive": True, "createdAt": "2026-09-18T00:00:00Z",
        "secret": "whsec-signing-secret",
    })
    assert hook.secret == "whsec-signing-secret"
    assert "whsec-signing-secret" not in repr(hook)
    assert "whsec-signing-secret" not in str(hook)
