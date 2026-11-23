"""RFC 9421 Signature-Input handling, held to the same cases as the TypeScript
SDK so both verifiers give one verdict for any delivery."""

from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from agledger.webhooks import verify_rfc9421
from agledger.webhooks._structured_fields import (
    InnerList,
    Item,
    parse_dictionary,
    serialize_inner_list,
)

IDK_HEADER = "x-agledger-idempotency-key"
BODY = json.dumps({"type": "signal.emitted", "data": {"recordId": "rec-1"}, "id": "evt-1"})
DIGEST = "sha-256=:" + base64.b64encode(hashlib.sha256(BODY.encode()).digest()).decode() + ":"
IDEM = "11111111-2222-3333-4444-555555555555"
COVERED = f'("content-digest" "{IDK_HEADER}")'

ED = ed25519.Ed25519PrivateKey.generate()
ED_SPKI = base64.b64encode(
    ED.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
).decode()
P256 = ec.generate_private_key(ec.SECP256R1())
P256_SPKI = base64.b64encode(
    P256.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
).decode()


def _now() -> int:
    return int(time.time())


def _sign_raw(private_key: object, base: str) -> str:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return base64.b64encode(private_key.sign(base.encode())).decode()
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    r, s = decode_dss_signature(private_key.sign(base.encode(), ec.ECDSA(hashes.SHA256())))
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def _deliver(params: str, private_key: object = ED, label: str = "sig1", signed_params: str | None = None) -> dict[str, str]:
    base = "\n".join(
        [f'"content-digest": {DIGEST}', f'"{IDK_HEADER}": {IDEM}', f'"@signature-params": {signed_params or params}']
    )
    return {
        "content-digest": DIGEST,
        IDK_HEADER: IDEM,
        "signature-input": f"{label}={params}",
        "signature": f"{label}=:{_sign_raw(private_key, base)}:",
    }


def _p(extra: str = "") -> str:
    return f'{COVERED};created={_now()};keyid="k1";alg="ed25519"{extra}'


def test_accepts_the_server_shape() -> None:
    assert verify_rfc9421(_deliver(_p()), BODY, ED_SPKI) is True


def test_accepts_unused_parameters_signed_as_sent_in_any_order() -> None:
    assert verify_rfc9421(_deliver(_p(';nonce="abc";tag="agledger"')), BODY, ED_SPKI) is True
    assert verify_rfc9421(_deliver(f'{COVERED};keyid="k1";alg="ed25519";created={_now()}'), BODY, ED_SPKI) is True


def test_rebuilds_signature_params_from_the_parsed_value() -> None:
    canonical = _p()
    spaced = canonical.replace('("content-digest" ', '(  "content-digest"   ').replace('")', '" )')
    assert verify_rfc9421(_deliver(spaced, signed_params=canonical), BODY, ED_SPKI) is True


def test_verifies_when_one_of_several_signatures_is_ours() -> None:
    ours = _deliver(_p())
    theirs = _deliver(f'("{IDK_HEADER}");created={_now()};keyid="proxy"', ed25519.Ed25519PrivateKey.generate(), "proxy")
    both = {
        **ours,
        "signature-input": f"{theirs['signature-input']}, {ours['signature-input']}",
        "signature": f"{theirs['signature']}, {ours['signature']}",
    }
    assert verify_rfc9421(both, BODY, ED_SPKI) is True
    only_theirs = {**ours, "signature-input": theirs["signature-input"], "signature": theirs["signature"]}
    assert verify_rfc9421(only_theirs, BODY, ED_SPKI) is False


def test_refuses_a_label_with_no_matching_signature() -> None:
    d = _deliver(_p())
    assert verify_rfc9421({**d, "signature": d["signature"].replace("sig1=", "sig2=")}, BODY, ED_SPKI) is False


def test_refuses_a_declared_alg_the_key_does_not_carry() -> None:
    assert verify_rfc9421(_deliver(f'{COVERED};created={_now()};keyid="k1";alg="ecdsa-p256-sha256"'), BODY, ED_SPKI) is False
    assert verify_rfc9421(_deliver(f'{COVERED};created={_now()};keyid="k1";alg="ed25519"', P256), BODY, P256_SPKI) is False


def test_verifies_es256() -> None:
    assert verify_rfc9421(_deliver(f'{COVERED};created={_now()};keyid="k1";alg="ecdsa-p256-sha256"', P256), BODY, P256_SPKI) is True


def test_holds_expires_when_present() -> None:
    assert verify_rfc9421(_deliver(_p(f";expires={_now() + 60}")), BODY, ED_SPKI) is True
    assert verify_rfc9421(_deliver(_p(f";expires={_now() - 400}")), BODY, ED_SPKI) is False


def test_requires_created_integer_and_keyid_string() -> None:
    for params in (
        f'{COVERED};created="{_now()}";keyid="k1"',
        f"{COVERED};created={_now()};keyid=k1",
        f"{COVERED};created={_now()}",
        f'{COVERED};keyid="k1"',
    ):
        assert verify_rfc9421(_deliver(params), BODY, ED_SPKI) is False, params


def test_covers_exactly_our_components_in_order_without_parameters() -> None:
    t = f';created={_now()};keyid="k1"'
    for inner in (f'("{IDK_HEADER}" "content-digest")', f'("content-digest";sf "{IDK_HEADER}")', f'("content-digest" "{IDK_HEADER}" "@method")', '("content-digest")'):
        assert verify_rfc9421(_deliver(inner + t), BODY, ED_SPKI) is False, inner


def test_refuses_an_es256_signature_that_is_not_64_bytes() -> None:
    d = _deliver(f'{COVERED};created={_now()};keyid="k1";alg="ecdsa-p256-sha256"', P256)
    short = base64.b64encode(base64.b64decode(d["signature"][len("sig1=:") : -1])[:63]).decode()
    assert verify_rfc9421({**d, "signature": f"sig1=:{short}:"}, BODY, P256_SPKI) is False


@pytest.mark.parametrize("bad", ["sig1=", "sig1=:not base64!:", "Sig1=:AAAA:", "sig1=:AAAA:,", "sig1=:AAAA: sig2=:AAAA:"])
def test_refuses_a_signature_field_that_is_not_a_dictionary(bad: str) -> None:
    assert verify_rfc9421({**_deliver(_p()), "signature": bad}, BODY, ED_SPKI) is False


@pytest.mark.parametrize(
    "bad", [f'sig1={COVERED};created=1.5;keyid="k1"', f'sig1={COVERED};created=1;keyid="k\\1"', 'sig1=("content-digest"']
)
def test_refuses_a_signature_input_that_is_not_a_dictionary(bad: str) -> None:
    assert verify_rfc9421({**_deliver(_p()), "signature-input": bad}, BODY, ED_SPKI) is False


def test_round_trips_an_inner_list_canonically() -> None:
    d = parse_dictionary('sig1=(  "a"   "b";x=1 );created=17;keyid="k\\"1";t=tok/en;f=?0;b=:AAE=:;flag')
    assert d is not None
    member = d["sig1"]
    assert isinstance(member, InnerList)
    assert serialize_inner_list(member) == '("a" "b";x=1);created=17;keyid="k\\"1";t=tok/en;f=?0;b=:AAE=:;flag'


def test_keeps_the_last_of_a_repeated_key() -> None:
    d = parse_dictionary("a=1, a=2")
    assert d is not None
    member = d["a"]
    assert isinstance(member, Item) and member.value == 2


@pytest.mark.parametrize("bad", [" , ", "A=1", "a=1,", "a=1 b=2", 'a="unterminated', "a=1234567890123456", "a=1.0", "a=?2", "a=(1 2"])
def test_refuses_what_is_not_a_dictionary(bad: str) -> None:
    assert parse_dictionary(bad) is None


def test_an_empty_field_is_an_empty_dictionary() -> None:
    assert parse_dictionary("") == {}


def test_an_integer_is_ascii_digits_only():
    from agledger.webhooks._structured_fields import parse_dictionary

    assert parse_dictionary("a=\u0661\u0662") is None
    assert parse_dictionary("a=12") is not None
