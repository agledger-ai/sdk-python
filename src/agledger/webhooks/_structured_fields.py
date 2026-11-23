"""The part of RFC 8941 (Structured Field Values for HTTP) that RFC 9421
``Signature-Input`` and ``Signature`` use: a Dictionary whose members are
Items or Inner Lists, with Parameters.

Parsing follows the RFC's algorithms and is strict: anything it does not
accept parses to ``None``, which the verifier treats as a delivery that does
not verify. A Decimal is refused rather than parsed: no RFC 9421 parameter is
one, and the TypeScript SDK refuses it the same way.

Serialization covers what the ``@signature-params`` line of a signature base
needs: an Inner List with its Parameters, in canonical form (RFC 8941 section
4.1), so the base is rebuilt from the parsed value, not from the bytes the
sender happened to send.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Token:
    value: str


@dataclass(frozen=True)
class ByteSequence:
    data: bytes


BareItem = int | str | bool | Token | ByteSequence


@dataclass
class Item:
    value: BareItem
    params: dict[str, BareItem]


@dataclass
class InnerList:
    items: list[Item]
    params: dict[str, BareItem]


Member = Item | InnerList

_KEY_START = re.compile(r"[a-z*]")
_KEY_CHAR = re.compile(r"[a-z0-9_\-.*]")
_INTEGER = re.compile(r"-?\d{1,15}")
_TOKEN = re.compile(r"[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")


class _ParseError(Exception):
    pass


class _Parser:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def next(self) -> str:
        c = self.peek()
        self.i += 1
        return c

    def expect(self, c: str) -> None:
        if self.next() != c:
            raise _ParseError(f"expected {c}")

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t") and self.peek() != "":
            self.i += 1

    def dictionary(self) -> dict[str, Member]:
        out: dict[str, Member] = {}
        self.skip_sp()
        while self.i < len(self.s):
            key = self.key()
            member: Member
            if self.peek() == "=":
                self.i += 1
                member = self.inner_list() if self.peek() == "(" else self.item()
            else:
                member = Item(True, self.parameters())
            out[key] = member
            self.skip_ows()
            if self.i >= len(self.s):
                return out
            if self.next() != ",":
                raise _ParseError("expected a comma between dictionary members")
            self.skip_ows()
            if self.i >= len(self.s):
                raise _ParseError("trailing comma")
        return out

    def inner_list(self) -> InnerList:
        self.expect("(")
        items: list[Item] = []
        while self.i < len(self.s):
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return InnerList(items, self.parameters())
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                raise _ParseError("expected a space or a closing parenthesis")
        raise _ParseError("unterminated inner list")

    def item(self) -> Item:
        return Item(self.bare_item(), self.parameters())

    def parameters(self) -> dict[str, BareItem]:
        params: dict[str, BareItem] = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            key = self.key()
            value: BareItem = True
            if self.peek() == "=":
                self.i += 1
                value = self.bare_item()
            params[key] = value
        return params

    def key(self) -> str:
        start = self.i
        if not _KEY_START.fullmatch(self.peek() or "!"):
            raise _ParseError("a key starts with a lowercase letter or *")
        while self.peek() and _KEY_CHAR.fullmatch(self.peek()):
            self.i += 1
        return self.s[start : self.i]

    def bare_item(self) -> BareItem:
        c = self.peek()
        if c == "-" or c.isdigit():
            return self.integer()
        if c == '"':
            return self.string()
        if c == ":":
            return self.byte_sequence()
        if c == "?":
            return self.boolean()
        if c and (c.isascii() and (c.isalpha() or c == "*")):
            return self.token()
        raise _ParseError("not a bare item")

    def integer(self) -> int:
        m = _INTEGER.match(self.s, self.i)
        if not m:
            raise _ParseError("not an integer")
        self.i = m.end()
        if self.peek() and (self.peek() == "." or self.peek().isdigit()):
            raise _ParseError("integer too long, or a decimal")
        return int(m.group(0))

    def string(self) -> str:
        self.expect('"')
        out: list[str] = []
        while self.i < len(self.s):
            c = self.next()
            if c == "\\":
                e = self.next()
                if e not in ('"', "\\"):
                    raise _ParseError("bad escape in string")
                out.append(e)
            elif c == '"':
                return "".join(out)
            else:
                if not (0x20 <= ord(c) <= 0x7E):
                    raise _ParseError("string holds a character outside printable ASCII")
                out.append(c)
        raise _ParseError("unterminated string")

    def token(self) -> Token:
        m = _TOKEN.match(self.s, self.i)
        if not m:
            raise _ParseError("not a token")
        self.i = m.end()
        return Token(m.group(0))

    def byte_sequence(self) -> ByteSequence:
        self.expect(":")
        end = self.s.find(":", self.i)
        if end < 0:
            raise _ParseError("unterminated byte sequence")
        b64 = self.s[self.i : end]
        if not _BASE64.fullmatch(b64) or len(b64) % 4 != 0:
            raise _ParseError("byte sequence is not base64")
        self.i = end + 1
        return ByteSequence(base64.b64decode(b64))

    def boolean(self) -> bool:
        self.expect("?")
        c = self.next()
        if c == "1":
            return True
        if c == "0":
            return False
        raise _ParseError("not a boolean")


def parse_dictionary(value: str) -> dict[str, Member] | None:
    """Parse an RFC 8941 Dictionary field value, or ``None`` if it is not one."""
    try:
        return _Parser(value.strip(" ")).dictionary()
    except _ParseError:
        return None


def _serialize_bare_item(v: BareItem) -> str:
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, Token):
        return v.value
    return ":" + base64.b64encode(v.data).decode("ascii") + ":"


def _serialize_parameters(params: dict[str, BareItem]) -> str:
    return "".join(f";{k}" if v is True else f";{k}={_serialize_bare_item(v)}" for k, v in params.items())


def serialize_inner_list(inner: InnerList) -> str:
    """Serialize an Inner List with its Parameters, canonically (RFC 8941 4.1.1.1)."""
    items = " ".join(_serialize_bare_item(i.value) + _serialize_parameters(i.params) for i in inner.items)
    return f"({items}){_serialize_parameters(inner.params)}"
