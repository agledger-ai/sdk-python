"""Strict reading of signed CBOR.

The signed bytes are deterministic CBOR (RFC 8949 section 4.2.1), so anything a
conforming encoder would not emit is refused rather than tolerated: duplicate
map keys (two readers could take different values), non-minimal integer and
length encodings, indefinite lengths, ``undefined``, invalid UTF-8, and bytes
after the item. ``cbor2`` accepts all of these, so :func:`check_strict` walks the
raw bytes before they are decoded. Mirrors verify-core's strict decode
options.
"""

from __future__ import annotations

#: The simple values a deterministic encoder emits: false, true and null.
_ALLOWED_SIMPLE = frozenset({20, 21, 22})
_MAX_DEPTH = 256
#: The smallest value each argument width may carry (one, two, four, eight bytes).
_MIN_BY_WIDTH = {1: 24, 2: 256, 4: 65536, 8: 2**32}


def check_strict(data: bytes) -> None:
    """Raise ``ValueError`` unless ``data`` is exactly one CBOR item in
    the strict form above."""
    end = _item(data, 0, 0)
    if end != len(data):
        raise ValueError("trailing bytes after the CBOR item")


def _argument(data: bytes, pos: int, info: int) -> tuple[int, int]:
    """The head argument at ``pos`` (just past the initial byte), and the
    position after it."""
    if info < 24:
        return info, pos
    if info > 27:
        raise ValueError("indefinite length or reserved additional information")
    width = 1 << (info - 24)
    if pos + width > len(data):
        raise ValueError("truncated CBOR head")
    value = int.from_bytes(data[pos : pos + width], "big")
    if value < _MIN_BY_WIDTH[width]:
        raise ValueError("integer or length encoded in more bytes than necessary")
    return value, pos + width


def _item(data: bytes, pos: int, depth: int) -> int:
    if depth > _MAX_DEPTH:
        raise ValueError("CBOR nested too deeply")
    if pos >= len(data):
        raise ValueError("truncated CBOR item")
    initial = data[pos]
    major, info = initial >> 5, initial & 31
    pos += 1
    if major == 7:
        if info in _ALLOWED_SIMPLE:
            return pos
        if info in (25, 26, 27):
            width = 1 << (info - 24)
            if pos + width > len(data):
                raise ValueError("truncated CBOR float")
            return pos + width
        raise ValueError("undefined, an unassigned simple value or a break where an item belongs")
    value, pos = _argument(data, pos, info)
    if major in (0, 1):
        return pos
    if major in (2, 3):
        if pos + value > len(data):
            raise ValueError("truncated CBOR string")
        if major == 3:
            try:
                data[pos : pos + value].decode("utf-8")
            except UnicodeDecodeError as err:
                raise ValueError("invalid UTF-8 in a text string") from err
        return pos + value
    if major == 6:
        return _item(data, pos, depth + 1)
    remaining = len(data) - pos
    if major == 4:
        if value > remaining:
            raise ValueError("truncated CBOR array")
        for _ in range(value):
            pos = _item(data, pos, depth + 1)
        return pos
    if value * 2 > remaining:
        raise ValueError("truncated CBOR map")
    seen: set[bytes] = set()
    for _ in range(value):
        start = pos
        pos = _item(data, pos, depth + 1)
        key = data[start:pos]
        if key in seen:
            raise ValueError("duplicate map key")
        seen.add(key)
        pos = _item(data, pos, depth + 1)
    return pos
