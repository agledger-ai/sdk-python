"""Signed CBOR is decoded strictly: duplicate map keys, non-minimal integers
and lengths, indefinite lengths, undefined, invalid UTF-8 and trailing bytes are
refused. Mirrors verify-core's strict decode tests."""

from __future__ import annotations

import pytest

from agledger.verify.cbor_strict import check_strict
from agledger.verify.verify_export import (
    _decode_predicate,  # pyright: ignore[reportPrivateUsage]
    _extract_chain_claim,  # pyright: ignore[reportPrivateUsage]
    cbor_whole,
)

REFUSED = {
    "duplicate map key": bytes([0xA2, 0x01, 0x01, 0x01, 0x02]),
    "non-minimal one-byte uint": bytes([0x18, 0x05]),
    "non-minimal two-byte uint": bytes([0x19, 0x00, 0xFF]),
    "non-minimal four-byte uint": bytes([0x1A, 0x00, 0x00, 0xFF, 0xFF]),
    "non-minimal eight-byte uint": bytes([0x1B, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]),
    "non-minimal negative integer": bytes([0x38, 0x05]),
    "non-minimal text length": bytes([0x78, 0x01, 0x61]),
    "non-minimal array length": bytes([0x98, 0x01, 0x01]),
    "non-minimal tag": bytes([0xD8, 0x02, 0x01]),
    "indefinite array": bytes([0x9F, 0x01, 0xFF]),
    "indefinite map": bytes([0xBF, 0x01, 0x01, 0xFF]),
    "indefinite text": bytes([0x7F, 0x61, 0x61, 0xFF]),
    "undefined": bytes([0xF7]),
    "invalid UTF-8": bytes([0x62, 0xC3, 0x28]),
    "trailing bytes": bytes([0x01, 0x01]),
    "truncated": bytes([0x82, 0x01]),
    "empty": b"",
    "duplicate key in a nested map": bytes([0x81, 0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]),
}

ACCEPTED = {
    "small uint": bytes([0x17]),
    "smallest one-byte uint": bytes([0x18, 0x18]),
    "largest one-byte uint": bytes([0x18, 0xFF]),
    "smallest two-byte uint": bytes([0x19, 0x01, 0x00]),
    "text map": bytes([0xA2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]),
    "int and text keys that look alike": bytes([0xA2, 0x01, 0x01, 0x61, 0x31, 0x02]),
    "null, true and false": bytes([0x83, 0xF6, 0xF5, 0xF4]),
    "float": bytes([0xFB, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0]),
    "tagged item": bytes([0xD2, 0x80]),
    "multi-byte UTF-8": bytes([0x62, 0xC3, 0xA9]),
}


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_check_strict_refuses(name: str) -> None:
    with pytest.raises(ValueError):
        check_strict(REFUSED[name])
    with pytest.raises(ValueError):
        cbor_whole(REFUSED[name])


@pytest.mark.parametrize("name", sorted(ACCEPTED))
def test_check_strict_accepts_what_a_deterministic_encoder_emits(name: str) -> None:
    check_strict(ACCEPTED[name])
    cbor_whole(ACCEPTED[name])


def test_a_protected_header_that_repeats_a_label_is_not_a_decodable_chain_claim() -> None:
    pair = bytes([0x3A, 0x00, 0x01, 0x00, 0x00, 0xA2, 0x01, 0x01, 0x02, 0xF6])  # -65537: {1: 1, 2: null}
    assert _extract_chain_claim(bytes([0xA1]) + pair) == (1, None)
    assert _extract_chain_claim(bytes([0xA2]) + pair + pair) is None


def test_a_statement_that_repeats_a_key_does_not_decode() -> None:
    key = bytes([0x69]) + b"predicate"
    assert _decode_predicate(bytes([0xA1]) + key + bytes([0xA1, 0x61, 0x61, 0x01])) == {"a": 1}
    assert _decode_predicate(bytes([0xA2]) + key + bytes([0xA0]) + key + bytes([0xA0])) is None


def test_a_statement_followed_by_trailing_bytes_does_not_decode() -> None:
    key = bytes([0x69]) + b"predicate"
    assert _decode_predicate(bytes([0xA1]) + key + bytes([0xA0, 0x00])) is None
