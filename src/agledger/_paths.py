"""
AGLedger SDK: URL path segment encoding.
"""

from __future__ import annotations

from urllib.parse import quote


def seg(part: object) -> str:
    """One URL path segment, percent-encoded.

    Every caller-supplied id goes through here before it is placed in a path,
    so a value such as ``"../admin/x?y=1#z"`` stays inside its own segment
    instead of steering the request to another route with the caller's
    credentials. Nothing is left unescaped, ``/`` included.

    ``.`` and ``..`` survive encoding and URL parsing still collapses them, so
    a segment that is exactly one of them raises ``ValueError``.
    """
    text = str(part)
    if text in (".", ".."):
        raise ValueError(f"{text!r} is not a valid path segment")
    return quote(text, safe="")
