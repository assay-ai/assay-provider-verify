"""Minimal RFC 8941 parser: dictionaries whose members are inner lists of
strings, integers, quoted strings, tokens or byte sequences, with parameters.
Only what the Assay signature headers need."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Union


class ParseError(Exception):
    pass


class Bytes:
    """A byte-sequence item; ``b64`` is the base64 text between the colons."""

    __slots__ = ("b64",)

    def __init__(self, b64: str) -> None:
        self.b64 = b64


Bare = Union[str, int, Bytes]
ParamValue = Union[Bare, bool]


class Member:
    __slots__ = ("items", "item", "params", "raw")

    def __init__(self, items: Optional[List[str]], item: Optional[Bare], params: Dict[str, ParamValue], raw: str) -> None:
        self.items = items  # inner list of strings, when the member is an inner list
        self.item = item  # single item, otherwise
        self.params = params
        self.raw = raw  # text after `name=` (inner list or item plus params)


_KEY_FIRST = re.compile(r"[a-z*]")
_KEY_REST = re.compile(r"[a-z0-9_\-.*]")
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_INT = re.compile(r"-?[0-9]{1,15}")
_TOKEN_FIRST = re.compile(r"[A-Za-z*]")
_TOKEN_REST = re.compile(r"[A-Za-z0-9!#$%&'*+\-.^_`|~:/]")


class _Cursor:
    def __init__(self, s: str) -> None:
        self.s = s
        self.i = 0

    def peek(self) -> Optional[str]:
        return self.s[self.i] if self.i < len(self.s) else None

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t"):
            self.i += 1

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1


def _parse_key(c: _Cursor) -> str:
    start = c.i
    first = c.peek()
    if first is None or not _KEY_FIRST.fullmatch(first):
        raise ParseError("bad key")
    while not c.eof() and _KEY_REST.fullmatch(c.s[c.i]):
        c.i += 1
    return c.s[start:c.i]


def _parse_bare(c: _Cursor) -> Bare:
    ch = c.peek()
    if ch == '"':
        c.i += 1
        out = []
        while True:
            if c.eof():
                raise ParseError("unterminated string")
            x = c.s[c.i]
            c.i += 1
            if x == '"':
                return "".join(out)
            if x == "\\":
                if c.eof():
                    raise ParseError("bad escape")
                n = c.s[c.i]
                c.i += 1
                if n not in ('"', "\\"):
                    raise ParseError("bad escape")
                out.append(n)
            else:
                if ord(x) < 0x20 or ord(x) > 0x7E:
                    raise ParseError("bad char")
                out.append(x)
    if ch == ":":
        c.i += 1
        end = c.s.find(":", c.i)
        if end < 0:
            raise ParseError("unterminated bytes")
        b64 = c.s[c.i:end]
        if not _B64.match(b64):
            raise ParseError("bad base64")
        c.i = end + 1
        return Bytes(b64)
    if ch is not None and (ch == "-" or ("0" <= ch <= "9" and ch.isascii())):
        m = _INT.match(c.s, c.i)
        if not m:
            raise ParseError("bad integer")
        c.i = m.end()
        if c.peek() == ".":
            raise ParseError("decimals unsupported")
        return int(m.group(0))
    if ch is not None and _TOKEN_FIRST.fullmatch(ch):
        start = c.i
        while not c.eof() and _TOKEN_REST.fullmatch(c.s[c.i]):
            c.i += 1
        return c.s[start:c.i]
    raise ParseError("bad item")


def _parse_params(c: _Cursor) -> Dict[str, ParamValue]:
    params: Dict[str, ParamValue] = {}
    while c.peek() == ";":
        c.i += 1
        c.skip_sp()
        key = _parse_key(c)
        value: ParamValue = True
        if c.peek() == "=":
            c.i += 1
            value = _parse_bare(c)
        params[key] = value
    return params


def parse_dictionary(text: str) -> Dict[str, Member]:
    c = _Cursor(text)
    out: Dict[str, Member] = {}
    c.skip_ows()
    while not c.eof():
        key = _parse_key(c)
        if c.peek() == "=":
            c.i += 1
            start = c.i
            if c.peek() == "(":
                c.i += 1
                items: List[str] = []
                while True:
                    c.skip_sp()
                    if c.peek() == ")":
                        c.i += 1
                        break
                    v = _parse_bare(c)
                    if not isinstance(v, str):
                        raise ParseError("inner list items must be strings")
                    items.append(v)
                    if c.peek() not in (" ", ")"):
                        raise ParseError("bad inner list")
                params = _parse_params(c)
                member = Member(items, None, params, c.s[start:c.i])
            else:
                item = _parse_bare(c)
                params = _parse_params(c)
                member = Member(None, item, params, c.s[start:c.i])
        else:
            member = Member(None, "true", _parse_params(c), "")
        out[key] = member
        c.skip_ows()
        if c.eof():
            break
        if c.peek() != ",":
            raise ParseError("expected comma")
        c.i += 1
        c.skip_ows()
        if c.eof():
            raise ParseError("trailing comma")
    return out
