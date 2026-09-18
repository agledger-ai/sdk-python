"""The OIDC cert credential and the bearer-token forms the clients accept.

Everything here runs against a mocked Server. The exchange body is checked
field by field against the ``POST /v1/auth/oidc/cert`` contract, and every
signature the credential produces is verified with the public key it bound, so
a test cannot pass on a signature that only looks right.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import agledger._oidc as oidc_module
from agledger import (
    AgledgerClient,
    AsyncAgledgerClient,
    AuthenticationError,
    ConfigurationError,
    OidcCertExchangeError,
    async_oidc_cert_credential,
    oidc_cert_credential,
)

BASE = "https://agledger.example.com"
EXCHANGE = f"{BASE}/v1/auth/oidc/cert"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt(sub: str, jti: str) -> str:
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"iss": "https://idp.example", "sub": sub, "aud": "agledger", "jti": jti}).encode())
    return f"{header}.{payload}.{_b64url(b'not-checked-client-side')}"


class FakeIdp:
    """A token source that hands out a new token id on every call."""

    def __init__(self, sub: str = "workload-7") -> None:
        self.sub = sub
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            self.calls += 1
            return _jwt(self.sub, f"jti-{self.calls}")


def _cert_response(n: int, lifetime_seconds: int = 600) -> httpx.Response:
    return httpx.Response(
        201,
        json={
            "cert": {
                "id": f"cert-{n}",
                "trustedIssuerId": "ti-1",
                "orgId": "org-1",
                "agentId": "agt-1",
                "oidcIss": "https://idp.example",
                "oidcSub": "workload-7",
                "publicKeyThumbprint": "sha256:" + "0" * 64,
                "scopes": ["records:read", "records:write"],
                "issuedAt": "2026-09-18T00:00:00.000Z",
                "expiresAt": f"2026-09-18T00:{lifetime_seconds // 60:02d}:{lifetime_seconds % 60:02d}.000Z",
                "signingKeyId": "vk-1",
                "revokedAt": None,
            },
            "certJws": f"cert-jws-{n}",
            "nextSteps": [],
        },
    )


class ExchangeRecorder:
    """Side effect for the exchange route: records every body, answers with a
    fresh cert each time."""

    def __init__(self, lifetime_seconds: int = 600) -> None:
        self.bodies: list[dict[str, Any]] = []
        self.lifetime_seconds = lifetime_seconds
        self._lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.bodies.append(json.loads(request.content))
            n = len(self.bodies)
        return _cert_response(n, self.lifetime_seconds)


def _public_key(body: dict[str, Any]) -> Ed25519PublicKey:
    x = body["publicKeyJwk"]["x"]
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [1000.0]
    monkeypatch.setattr(oidc_module, "_monotonic", lambda: now[0])
    return now


# --- the exchange ---


@respx.mock
def test_the_exchange_body_matches_the_contract():
    recorder = ExchangeRecorder()
    respx.post(EXCHANGE).mock(side_effect=recorder)
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    idp = FakeIdp()

    client = AgledgerClient(
        bearer_token=oidc_cert_credential(get_oidc_token=idp, agent_id="agt-1"), base_url=BASE
    )
    client.request("GET", "/v1/auth/me")

    assert len(recorder.bodies) == 1
    body = recorder.bodies[0]
    assert set(body) == {"oidcToken", "publicKeyJwk", "proofOfPossession", "agentId"}
    assert body["oidcToken"] == _jwt("workload-7", "jti-1")
    assert body["agentId"] == "agt-1"
    jwk = body["publicKeyJwk"]
    assert set(jwk) == {"kty", "crv", "x"}
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519"
    assert len(base64.urlsafe_b64decode(jwk["x"] + "=")) == 32

    # STANDARD base64, 88 characters, '==' padded, never base64url.
    pop = body["proofOfPossession"]
    assert len(pop) == 88 and pop.endswith("==")
    assert "-" not in pop and "_" not in pop
    _public_key(body).verify(base64.b64decode(pop), b"agledger.oidc.cert.v1\nworkload-7")

    # The exchange itself carries no Authorization; the request after it
    # carries the cert.
    exchange_request = respx.calls[0].request
    assert "authorization" not in exchange_request.headers
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-1"


@respx.mock
def test_agent_id_is_left_off_when_not_given():
    recorder = ExchangeRecorder()
    respx.post(EXCHANGE).mock(side_effect=recorder)
    respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)
    client.request("GET", "/v1/auth/me")
    assert "agentId" not in recorder.bodies[0]


@respx.mock
def test_the_cert_is_reused_until_the_refresh_point(clock: list[float]):
    recorder = ExchangeRecorder(lifetime_seconds=120)
    respx.post(EXCHANGE).mock(side_effect=recorder)
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    idp = FakeIdp()
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=idp), base_url=BASE)

    client.request("GET", "/v1/auth/me")
    clock[0] += 59  # just short of half of 120s
    client.request("GET", "/v1/auth/me")
    assert len(recorder.bodies) == 1
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-1"

    clock[0] += 1  # at the refresh point
    client.request("GET", "/v1/auth/me")
    assert len(recorder.bodies) == 2
    assert idp.calls == 2, "every exchange must fetch a fresh OIDC token"
    assert recorder.bodies[0]["oidcToken"] != recorder.bodies[1]["oidcToken"]
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-2"


@respx.mock
def test_refresh_fraction_moves_the_refresh_point(clock: list[float]):
    recorder = ExchangeRecorder(lifetime_seconds=600)
    respx.post(EXCHANGE).mock(side_effect=recorder)
    respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    client = AgledgerClient(
        bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp(), refresh_fraction=0.8), base_url=BASE
    )
    client.request("GET", "/v1/auth/me")
    clock[0] += 479
    client.request("GET", "/v1/auth/me")
    assert len(recorder.bodies) == 1
    clock[0] += 1
    client.request("GET", "/v1/auth/me")
    assert len(recorder.bodies) == 2


@pytest.mark.parametrize("fraction", [0, -0.5, 1.5])
def test_refresh_fraction_out_of_range_is_refused(fraction: float):
    with pytest.raises(ConfigurationError, match="refresh_fraction"):
        oidc_cert_credential(get_oidc_token=FakeIdp(), refresh_fraction=fraction)


# --- 401 handling ---


@respx.mock
def test_a_401_forces_exactly_one_re_exchange_and_one_retry():
    recorder = ExchangeRecorder()
    respx.post(EXCHANGE).mock(side_effect=recorder)
    me = respx.get(f"{BASE}/v1/auth/me").mock(
        side_effect=[httpx.Response(401, json={"message": "cert revoked"}), httpx.Response(200, json={"ok": 1})]
    )
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)

    assert client.request("GET", "/v1/auth/me") == {"ok": 1}
    assert len(recorder.bodies) == 2
    assert [c.request.headers["authorization"] for c in me.calls] == [
        "Bearer cert-jws-1",
        "Bearer cert-jws-2",
    ]


@respx.mock
def test_a_second_401_surfaces_as_an_authentication_error():
    recorder = ExchangeRecorder()
    respx.post(EXCHANGE).mock(side_effect=recorder)
    me = respx.get(f"{BASE}/v1/auth/me").mock(
        return_value=httpx.Response(401, json={"message": "no", "code": "UNAUTHORIZED"})
    )
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)

    with pytest.raises(AuthenticationError):
        client.request("GET", "/v1/auth/me")
    assert len(recorder.bodies) == 2
    assert me.call_count == 2


@respx.mock
def test_a_401_on_an_api_key_is_not_retried():
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(401, json={"message": "no"}))
    client = AgledgerClient(api_key="agl_agt_x", base_url=BASE)
    with pytest.raises(AuthenticationError):
        client.request("GET", "/v1/auth/me")
    assert me.call_count == 1


@respx.mock
def test_a_refused_exchange_names_the_exchange_and_carries_the_recovery_hint():
    respx.post(EXCHANGE).mock(
        return_value=httpx.Response(
            409,
            json={
                "message": "This OIDC token id has already been exchanged",
                "code": "CONFLICT",
                "recoveryHint": "Fetch a new token from your IdP and exchange that.",
            },
        )
    )
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)

    with pytest.raises(OidcCertExchangeError) as info:
        client.request("GET", "/v1/auth/me")
    err = info.value
    assert not isinstance(err, AuthenticationError)
    assert err.status == 409
    assert "OIDC cert exchange failed" in str(err)
    assert "already been exchanged" in str(err)
    assert err.recovery_hint == "Fetch a new token from your IdP and exchange that."
    assert me.call_count == 0, "the request is never sent without a cert"


@respx.mock
def test_a_refused_exchange_never_carries_the_oidc_token():
    # The Server's 400 echoes the submitted input in details[].received, and an
    # exception is what gets logged. The token must not survive into it.
    idp = FakeIdp()
    token = _jwt("workload-7", "jti-1")

    def refuse(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        return httpx.Response(
            400,
            json={
                "message": f"body/proofOfPossession must match pattern; got token {sent['oidcToken']}",
                "code": "VALIDATION_ERROR",
                "details": [
                    {"path": "/proofOfPossession", "received": sent},
                    {"path": "/oidcToken", "received": sent["oidcToken"]},
                ],
                "recoveryHint": f"Re-send {sent['oidcToken'][:10]} with a valid proof.",
            },
        )

    respx.post(EXCHANGE).mock(side_effect=refuse)
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=idp), base_url=BASE)
    with pytest.raises(OidcCertExchangeError) as info:
        client.request("GET", "/v1/auth/me")
    err = info.value
    rendered = " ".join([str(err), repr(err), json.dumps(err.details), str(err.recovery_hint)])
    assert token not in rendered
    assert err.details[0]["received"]["oidcToken"] == "[redacted]"
    assert err.details[1]["received"] == "[redacted]"
    assert "[redacted]" in str(err)
    # What is not the token survives, so the error still says what was wrong.
    assert err.details[0]["path"] == "/proofOfPossession"
    assert err.code == "VALIDATION_ERROR"


def test_a_token_source_that_returns_no_jwt_is_a_configuration_error():
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=lambda: "opaque"), base_url=BASE)
    with pytest.raises(ConfigurationError, match="compact JWS"):
        client.request("GET", "/v1/auth/me")


# --- a token source that hands back a token it already gave ---


class FileLikeIdp:
    """A projected token file: the same token until the platform rotates it."""

    def __init__(self, *, jti: bool = True) -> None:
        self.generation = 1
        self.calls = 0
        self.jti = jti

    def rotate(self) -> None:
        self.generation += 1

    def __call__(self) -> str:
        self.calls += 1
        if self.jti:
            return _jwt("workload-7", f"file-{self.generation}")
        header = _b64url(json.dumps({"alg": "RS256"}).encode())
        payload = _b64url(json.dumps({"sub": "workload-7", "gen": self.generation}).encode())
        return f"{header}.{payload}.{_b64url(b'sig')}"


class JtiServer:
    """The exchange as the Server runs it: a token carrying a jti is taken once."""

    def __init__(self, lifetime_seconds: int = 120) -> None:
        self.recorder = ExchangeRecorder(lifetime_seconds)
        self.seen: set[str] = set()
        self.refused = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        token = json.loads(request.content)["oidcToken"]
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        if "jti" in claims and claims["jti"] in self.seen:
            self.refused += 1
            return httpx.Response(409, json={
                "message": "This OIDC token id has already been exchanged",
                "code": "CONFLICT",
                "recoveryHint": "Fetch a fresh token from your IdP.",
            })
        if "jti" in claims:
            self.seen.add(claims["jti"])
        return self.recorder(request)


@respx.mock
def test_a_scheduled_refresh_that_gets_the_same_token_keeps_the_valid_cert(clock: list[float]):
    server = JtiServer(lifetime_seconds=120)
    exchange = respx.post(EXCHANGE).mock(side_effect=server)
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    idp = FileLikeIdp()
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=idp), base_url=BASE)

    client.request("GET", "/v1/auth/me")
    clock[0] += 70  # past the refresh point, inside the 120s lifetime
    client.request("GET", "/v1/auth/me")
    assert exchange.call_count == 1, "an unchanged token with a jti is not sent again"
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-1"

    idp.rotate()  # the platform writes a new token to the file
    client.request("GET", "/v1/auth/me")
    assert exchange.call_count == 2
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-2"


@respx.mock
def test_a_scheduled_refresh_refused_as_already_exchanged_keeps_the_valid_cert(clock: list[float]):
    # A token source that returns a token the Server has seen, but that this
    # credential never sent (another process exchanged it first).
    respx.post(EXCHANGE).mock(side_effect=[
        _cert_response(1, 120),
        httpx.Response(409, json={"message": "This OIDC token id has already been exchanged"}),
        _cert_response(2, 120),
    ])
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)

    client.request("GET", "/v1/auth/me")
    clock[0] += 70
    client.request("GET", "/v1/auth/me")  # the 409 is absorbed
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-1"
    client.request("GET", "/v1/auth/me")  # and the next request tries again
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-2"


@respx.mock
def test_an_already_exchanged_token_after_expiry_raises_saying_so(clock: list[float]):
    server = JtiServer(lifetime_seconds=120)
    respx.post(EXCHANGE).mock(side_effect=server)
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FileLikeIdp()), base_url=BASE)

    client.request("GET", "/v1/auth/me")
    clock[0] += 121  # the cert has expired and the file still holds the old token
    with pytest.raises(OidcCertExchangeError) as info:
        client.request("GET", "/v1/auth/me")
    assert info.value.status == 409
    assert "already exchanged" in str(info.value)
    assert "must return a new token" in str(info.value)
    assert me.call_count == 1


@respx.mock
def test_an_already_exchanged_token_on_a_401_raises_saying_so():
    server = JtiServer()
    respx.post(EXCHANGE).mock(side_effect=server)
    respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(401, json={"message": "revoked"}))
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FileLikeIdp()), base_url=BASE)

    with pytest.raises(OidcCertExchangeError, match="must return a new token"):
        client.request("GET", "/v1/auth/me")
    assert server.refused == 1


@respx.mock
def test_a_token_without_a_jti_is_exchanged_again_at_the_refresh_point(clock: list[float]):
    # With no jti the Server does not deduplicate, so the same token renews.
    server = JtiServer(lifetime_seconds=120)
    exchange = respx.post(EXCHANGE).mock(side_effect=server)
    respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    client = AgledgerClient(
        bearer_token=oidc_cert_credential(get_oidc_token=FileLikeIdp(jti=False)), base_url=BASE
    )
    client.request("GET", "/v1/auth/me")
    clock[0] += 70
    client.request("GET", "/v1/auth/me")
    assert exchange.call_count == 2
    assert server.refused == 0


@respx.mock
async def test_async_a_scheduled_refresh_that_gets_the_same_token_keeps_the_valid_cert(clock: list[float]):
    exchange = respx.post(EXCHANGE).mock(side_effect=JtiServer(lifetime_seconds=120))
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    async with AsyncAgledgerClient(
        bearer_token=async_oidc_cert_credential(get_oidc_token=FileLikeIdp()), base_url=BASE
    ) as client:
        await client.request("GET", "/v1/auth/me")
        clock[0] += 70
        await client.request("GET", "/v1/auth/me")
    assert exchange.call_count == 1
    assert me.calls.last.request.headers["authorization"] == "Bearer cert-jws-1"


# --- concurrency ---


@respx.mock
def test_concurrent_requests_share_one_exchange():
    gate = threading.Event()

    def slow_exchange(request: httpx.Request) -> httpx.Response:
        gate.wait(2)
        return recorder(request)

    recorder = ExchangeRecorder()
    respx.post(EXCHANGE).mock(side_effect=slow_exchange)
    respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    idp = FakeIdp()
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=idp), base_url=BASE)

    threads = [threading.Thread(target=client.request, args=("GET", "/v1/auth/me")) for _ in range(8)]
    for t in threads:
        t.start()
    time.sleep(0.1)
    gate.set()
    for t in threads:
        t.join(5)

    assert len(recorder.bodies) == 1
    assert idp.calls == 1


@respx.mock
def test_concurrent_401s_share_one_re_exchange():
    recorder = ExchangeRecorder()
    respx.post(EXCHANGE).mock(side_effect=recorder)
    barrier = threading.Barrier(4)

    def me(request: httpx.Request) -> httpx.Response:
        if request.headers["authorization"] == "Bearer cert-jws-1":
            barrier.wait(2)  # all four hold the stale cert at once
            return httpx.Response(401, json={"message": "expired"})
        return httpx.Response(200, json={})

    respx.get(f"{BASE}/v1/auth/me").mock(side_effect=me)
    credential_client = AgledgerClient(
        bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE
    )
    credential_client._http._token(False)  # prime the first cert  # pyright: ignore[reportPrivateUsage]

    errors: list[BaseException] = []

    def run() -> None:
        try:
            credential_client.request("GET", "/v1/auth/me")
        except BaseException as e:  # pragma: no cover - surfaced below
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert errors == []
    assert len(recorder.bodies) == 2, "four refused requests, one re-exchange"


@respx.mock
async def test_async_concurrent_requests_share_one_exchange():
    recorder = ExchangeRecorder()

    async def slow_exchange(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return recorder(request)

    respx.post(EXCHANGE).mock(side_effect=slow_exchange)
    respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))

    calls = 0

    async def idp() -> str:
        nonlocal calls
        calls += 1
        return _jwt("workload-7", f"jti-{calls}")

    async with AsyncAgledgerClient(
        bearer_token=async_oidc_cert_credential(get_oidc_token=idp), base_url=BASE
    ) as client:
        await asyncio.gather(*(client.request("GET", "/v1/auth/me") for _ in range(8)))

    assert len(recorder.bodies) == 1
    assert calls == 1


@respx.mock
async def test_async_a_401_forces_one_re_exchange():
    recorder = ExchangeRecorder()
    respx.post(EXCHANGE).mock(side_effect=recorder)
    respx.get(f"{BASE}/v1/auth/me").mock(
        side_effect=[httpx.Response(401, json={}), httpx.Response(200, json={"ok": 1})]
    )
    async with AsyncAgledgerClient(
        bearer_token=async_oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE
    ) as client:
        assert await client.request("GET", "/v1/auth/me") == {"ok": 1}
    assert len(recorder.bodies) == 2


# --- body signing ---


@respx.mock
def test_a_request_body_is_signed_over_exactly_the_bytes_sent():
    recorder = ExchangeRecorder()
    respx.post(EXCHANGE).mock(side_effect=recorder)
    create = respx.post(f"{BASE}/v1/records").mock(
        return_value=httpx.Response(201, json={"id": "rec-1"})
    )
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)
    client.request("POST", "/v1/records", json={"type": "notarize-generic-v1", "criteria": {"note": "héllo"}})

    request = create.calls.last.request
    sent = request.content
    digest = hashlib.sha256(sent).hexdigest()
    assert request.headers["x-agent-signature-content-hash"] == f"sha256:{digest}"
    signature = request.headers["x-agent-signature"]
    assert len(signature) == 88 and signature.endswith("==")
    # The Server verifies over its context prefix plus the HEX string, not the
    # digest bytes.
    _public_key(recorder.bodies[0]).verify(
        base64.b64decode(signature), f"agledger.agent.sig.v1\n{digest}".encode()
    )


@respx.mock
def test_a_request_without_a_body_is_not_signed():
    respx.post(EXCHANGE).mock(side_effect=ExchangeRecorder())
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    client = AgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)
    client.request("GET", "/v1/auth/me")
    assert "x-agent-signature" not in me.calls.last.request.headers
    assert "x-agent-signature-content-hash" not in me.calls.last.request.headers


@respx.mock
def test_an_api_key_client_sends_no_signature_headers():
    create = respx.post(f"{BASE}/v1/records").mock(return_value=httpx.Response(201, json={"id": "rec-1"}))
    AgledgerClient(api_key="agl_agt_x", base_url=BASE).request("POST", "/v1/records", json={"a": 1})
    assert "x-agent-signature" not in create.calls.last.request.headers


# --- function-form bearers and configuration ---


@respx.mock
def test_a_function_bearer_is_called_on_every_request_and_never_cached():
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    minted: list[str] = []

    def token() -> str:
        minted.append(f"idp-token-{len(minted) + 1}")
        return minted[-1]

    client = AgledgerClient(bearer_token=token, base_url=BASE)
    client.request("GET", "/v1/auth/me")
    client.request("GET", "/v1/auth/me")
    assert [c.request.headers["authorization"] for c in me.calls] == [
        "Bearer idp-token-1",
        "Bearer idp-token-2",
    ]


@respx.mock
def test_a_function_bearer_is_called_again_on_a_retried_attempt(monkeypatch: pytest.MonkeyPatch):
    # With jtiSingleUse on the issuer, resending a token after a 503 would be
    # refused as a replay, so each attempt asks the function again.
    monkeypatch.setattr("agledger._http.time.sleep", lambda _s: None)
    me = respx.get(f"{BASE}/v1/auth/me").mock(
        side_effect=[httpx.Response(503, json={}), httpx.Response(200, json={})]
    )
    minted: list[str] = []

    def token() -> str:
        minted.append(f"t{len(minted)}")
        return minted[-1]

    AgledgerClient(bearer_token=token, base_url=BASE).request("GET", "/v1/auth/me")
    assert [c.request.headers["authorization"] for c in me.calls] == ["Bearer t0", "Bearer t1"]


@respx.mock
async def test_an_async_function_bearer_may_be_a_coroutine():
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))

    async def token() -> str:
        return "from-coroutine"

    async with AsyncAgledgerClient(bearer_token=token, base_url=BASE) as client:
        await client.request("GET", "/v1/auth/me")
    assert me.calls.last.request.headers["authorization"] == "Bearer from-coroutine"


@respx.mock
def test_a_string_bearer_is_sent_as_is():
    me = respx.get(f"{BASE}/v1/auth/me").mock(return_value=httpx.Response(200, json={}))
    AgledgerClient(bearer_token="static-jwt", base_url=BASE).request("GET", "/v1/auth/me")
    assert me.calls.last.request.headers["authorization"] == "Bearer static-jwt"


def test_api_key_and_bearer_token_together_are_refused(monkeypatch: pytest.MonkeyPatch):
    with pytest.raises(ConfigurationError, match="not both"):
        AgledgerClient(api_key="agl_agt_x", bearer_token="jwt", base_url=BASE)


def test_bearer_token_wins_over_the_env_api_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGLEDGER_API_KEY", "agl_agt_env")
    client = AgledgerClient(bearer_token="jwt", base_url=BASE)
    assert client._http._credential == "jwt"  # pyright: ignore[reportPrivateUsage]


def test_a_sync_credential_on_the_async_client_is_refused():
    with pytest.raises(ConfigurationError, match="synchronous"):
        AsyncAgledgerClient(bearer_token=oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)  # pyright: ignore[reportArgumentType]


def test_an_async_credential_on_the_sync_client_is_refused():
    with pytest.raises(ConfigurationError, match="asynchronous"):
        AgledgerClient(bearer_token=async_oidc_cert_credential(get_oidc_token=FakeIdp()), base_url=BASE)  # pyright: ignore[reportArgumentType]


def test_the_private_key_is_not_in_the_repr():
    credential = oidc_cert_credential(get_oidc_token=FakeIdp(), agent_id="agt-1")
    assert repr(credential) == "OidcCertCredential(agent_id='agt-1', refresh_fraction=0.5)"
    assert credential.cert is None
    assert set(credential.public_key_jwk) == {"kty", "crv", "x"}
