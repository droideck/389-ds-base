"""Standard-library primitives shared by the workload generator.

The evaluator is deliberately independent of either LDAP server.  It models
only the matching rules used by the generated workload and treats malformed
DN assertions as non-matching remainder branches.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import unicodedata

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Mapping, Optional, Sequence, Tuple


DN_ATTRIBUTES = frozenset({"sdn1", "sdn2", "member"})
STRING_ATTRIBUTES = frozenset({
    "uid", "cn", "sn", "objectclass", "sstring1", "sstring2",
    "sstring3", "sstring4", "ssub", "sapprox",
})
_ATTR_RE = re.compile(r"(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)*)\Z")
_HEX = frozenset("0123456789abcdefABCDEF")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


@contextmanager
def atomic_output_directory(target: Path) -> Iterator[Path]:
    """Yield a sibling temporary directory and atomically publish it.

    Existing targets are rejected.  This avoids a partially refreshed output
    tree and makes a failed generation leave the previous filesystem state
    untouched.
    """
    if target.is_symlink():
        raise FileExistsError(f"output already exists as a symlink: {target}")
    target = target.resolve()
    if target.exists():
        raise FileExistsError(f"output already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(
        prefix=f".{target.name}.tmp-", dir=str(target.parent)
    ))
    published = False
    try:
        yield temporary
        os.replace(temporary, target)
        published = True
        directory_fd = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if not published and temporary.exists():
            shutil.rmtree(temporary)


def normalize_directory_string(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(normalized.split())


def normalize_approx(value: str) -> str:
    """Conservative, deterministic approximate oracle for generated tokens.

    Generated approximate positives are identical after this normalization;
    negative values use disjoint alphanumeric tokens.  The manifest marks the
    scenario separately because server phonetic algorithms are implementation
    details rather than a cross-server correctness oracle.
    """
    decomposed = unicodedata.normalize("NFKD", value).casefold()
    return "".join(
        char for char in decomposed
        if char.isalnum() and not unicodedata.combining(char)
    )


def _split_unescaped(value: str, delimiter: str) -> Sequence[str]:
    parts = []
    start = 0
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            if index + 1 >= len(value):
                raise ValueError("trailing DN escape")
            if (index + 2 < len(value) and value[index + 1] in _HEX
                    and value[index + 2] in _HEX):
                index += 3
            else:
                index += 2
            continue
        if char == delimiter:
            parts.append(value[start:index])
            start = index + 1
        index += 1
    parts.append(value[start:])
    return parts


def _split_first_unescaped(value: str, delimiter: str) -> Tuple[str, str]:
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            if index + 1 >= len(value):
                raise ValueError("trailing DN escape")
            if (index + 2 < len(value) and value[index + 1] in _HEX
                    and value[index + 2] in _HEX):
                index += 3
            else:
                index += 2
            continue
        if char == delimiter:
            return value[:index], value[index + 1:]
        index += 1
    raise ValueError(f"DN component lacks {delimiter!r}")


def _decode_dn_escapes(value: str) -> str:
    output = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\":
            output.extend(char.encode("utf-8"))
            index += 1
            continue
        if index + 1 >= len(value):
            raise ValueError("trailing DN escape")
        if (index + 2 < len(value) and value[index + 1] in _HEX
                and value[index + 2] in _HEX):
            output.append(int(value[index + 1:index + 3], 16))
            index += 3
        else:
            output.extend(value[index + 1].encode("utf-8"))
            index += 2
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("DN escape is not valid UTF-8") from error


def normalize_dn(value: str) -> Optional[Tuple[Tuple[Tuple[str, str], ...], ...]]:
    """Return a comparison key for the generated RFC4514 DN subset.

    RDN order is preserved and AVAs in a multi-valued RDN are sorted.  Attribute
    names, Unicode case, insignificant surrounding whitespace, repeated value
    whitespace, simple escapes, and hexadecimal escapes are normalized.
    """
    try:
        rdns = []
        for raw_rdn in _split_unescaped(value.strip(), ","):
            if not raw_rdn.strip():
                raise ValueError("empty RDN")
            avas = []
            for raw_ava in _split_unescaped(raw_rdn, "+"):
                raw_attr, raw_value = _split_first_unescaped(raw_ava, "=")
                attr = raw_attr.strip().casefold()
                if not _ATTR_RE.fullmatch(attr):
                    raise ValueError("invalid DN attribute type")
                decoded = _decode_dn_escapes(raw_value.strip())
                avas.append((attr, normalize_directory_string(decoded)))
            rdns.append(tuple(sorted(avas)))
        if not rdns:
            raise ValueError("empty DN")
        return tuple(rdns)
    except ValueError:
        return None


def normalize_equality(attr: str, value: str) -> Optional[Any]:
    attr_lower = attr.casefold()
    if attr_lower in DN_ATTRIBUTES:
        return normalize_dn(value)
    return normalize_directory_string(value)


def escape_filter_value(value: str) -> str:
    pieces = []
    for char in value:
        if char == "\x00":
            pieces.append("\\00")
        elif char == "*":
            pieces.append("\\2a")
        elif char == "(":
            pieces.append("\\28")
        elif char == ")":
            pieces.append("\\29")
        elif char == "\\":
            pieces.append("\\5c")
        else:
            pieces.append(char)
    return "".join(pieces)


def _match_substring(value: str, pattern: str) -> bool:
    candidate = normalize_directory_string(value)
    parts = [normalize_directory_string(part) for part in pattern.split("*")]
    if parts[0] and not candidate.startswith(parts[0]):
        return False
    if parts[-1] and not candidate.endswith(parts[-1]):
        return False
    position = len(parts[0])
    terminal = len(candidate) - len(parts[-1])
    for part in parts[1:-1]:
        if not part:
            continue
        found = candidate.find(part, position)
        if found < 0 or found + len(part) > terminal:
            return False
        position = found + len(part)
    return True


@dataclass(frozen=True)
class Filter:
    kind: str
    attr: Optional[str] = None
    value: Optional[str] = None
    children: Tuple["Filter", ...] = ()

    def render(self) -> str:
        if self.kind == "and":
            return "(&%s)" % "".join(child.render() for child in self.children)
        if self.kind == "or":
            return "(|%s)" % "".join(child.render() for child in self.children)
        if self.kind == "not":
            return "(!%s)" % self.children[0].render()
        if self.kind == "eq":
            return f"({self.attr}={escape_filter_value(self.value or '')})"
        if self.kind == "approx":
            return f"({self.attr}~={escape_filter_value(self.value or '')})"
        if self.kind == "present":
            return f"({self.attr}=*)"
        if self.kind == "substring":
            rendered = "*".join(
                escape_filter_value(part) for part in (self.value or "").split("*")
            )
            return f"({self.attr}={rendered})"
        raise ValueError(f"unsupported filter node: {self.kind}")

    def node_count(self) -> int:
        return 1 + sum(child.node_count() for child in self.children)

    def leaf_count(self) -> int:
        if self.kind in {"and", "or", "not"}:
            return sum(child.leaf_count() for child in self.children)
        return 1

    def equality_count(self) -> int:
        return ((1 if self.kind == "eq" else 0)
                + sum(child.equality_count() for child in self.children))

    def evaluate(self, data: "DataSet") -> set[int]:
        if self.kind == "and":
            values = sorted(
                (child.evaluate(data) for child in self.children), key=len
            )
            if not values:
                return set(data.all_ids)
            result = set(values[0])
            for value in values[1:]:
                result.intersection_update(value)
                if not result:
                    break
            return result
        if self.kind == "or":
            result: set[int] = set()
            for child in self.children:
                result.update(child.evaluate(data))
            return result
        if self.kind == "not":
            return set(data.all_ids).difference(self.children[0].evaluate(data))
        if self.kind == "eq":
            key = normalize_equality(self.attr or "", self.value or "")
            if key is None:
                return set()
            return set(data.equality.get((self.attr or "").casefold(), {}).get(key, ()))
        if self.kind == "present":
            return set(data.presence.get((self.attr or "").casefold(), ()))
        if self.kind == "substring":
            result: set[int] = set()
            for raw_value, ids in data.values.get((self.attr or "").casefold(), {}).items():
                if _match_substring(raw_value, self.value or ""):
                    result.update(ids)
            return result
        if self.kind == "approx":
            key = normalize_approx(self.value or "")
            return set(data.approx.get((self.attr or "").casefold(), {}).get(key, ()))
        raise ValueError(f"unsupported filter node: {self.kind}")

    def ber(self) -> bytes:
        if self.kind == "and":
            return _ber_tlv(0xA0, b"".join(child.ber() for child in self.children))
        if self.kind == "or":
            return _ber_tlv(0xA1, b"".join(child.ber() for child in self.children))
        if self.kind == "not":
            return _ber_tlv(0xA2, self.children[0].ber())
        if self.kind in {"eq", "approx"}:
            content = _ber_octets(self.attr or "") + _ber_octets(self.value or "")
            return _ber_tlv(0xA3 if self.kind == "eq" else 0xA8, content)
        if self.kind == "present":
            return _ber_tlv(0x87, (self.attr or "").encode("utf-8"))
        if self.kind == "substring":
            parts = (self.value or "").split("*")
            choices = []
            if parts[0]:
                choices.append(_ber_tlv(0x80, parts[0].encode("utf-8")))
            for part in parts[1:-1]:
                if part:
                    choices.append(_ber_tlv(0x81, part.encode("utf-8")))
            if parts[-1]:
                choices.append(_ber_tlv(0x82, parts[-1].encode("utf-8")))
            content = _ber_octets(self.attr or "") + _ber_tlv(0x30, b"".join(choices))
            return _ber_tlv(0xA4, content)
        raise ValueError(f"unsupported filter node: {self.kind}")


def AND(*children: Filter) -> Filter:
    return Filter("and", children=tuple(children))


def OR(*children: Filter) -> Filter:
    return Filter("or", children=tuple(children))


def NOT(child: Filter) -> Filter:
    return Filter("not", children=(child,))


def EQ(attr: str, value: str) -> Filter:
    return Filter("eq", attr=attr, value=value)


def APPROX(attr: str, value: str) -> Filter:
    return Filter("approx", attr=attr, value=value)


def PRESENT(attr: str) -> Filter:
    return Filter("present", attr=attr)


def SUBSTRING(attr: str, pattern: str) -> Filter:
    if "*" not in pattern:
        raise ValueError("substring pattern must contain a wildcard")
    return Filter("substring", attr=attr, value=pattern)


class DataSet:
    """Minimal inverted representation used by the data-derived oracle."""

    def __init__(self) -> None:
        self.dns: list[str] = []
        self.all_ids: set[int] = set()
        self.equality: Dict[str, Dict[Any, set[int]]] = {}
        self.approx: Dict[str, Dict[str, set[int]]] = {}
        self.presence: Dict[str, set[int]] = {}
        self.values: Dict[str, Dict[str, set[int]]] = {}

    def add(self, dn: str, attrs: Mapping[str, Sequence[str]]) -> int:
        entry_id = len(self.dns)
        self.dns.append(dn)
        self.all_ids.add(entry_id)
        for attr, raw_values in attrs.items():
            attr_lower = attr.casefold()
            if not raw_values:
                continue
            self.presence.setdefault(attr_lower, set()).add(entry_id)
            for raw_value in raw_values:
                key = normalize_equality(attr_lower, raw_value)
                if key is not None:
                    self.equality.setdefault(attr_lower, {}).setdefault(key, set()).add(entry_id)
                if attr_lower == "sapprox":
                    approx_key = normalize_approx(raw_value)
                    self.approx.setdefault(attr_lower, {}).setdefault(approx_key, set()).add(entry_id)
                self.values.setdefault(attr_lower, {}).setdefault(raw_value, set()).add(entry_id)
        return entry_id

    def sorted_dns(self, ids: Iterable[int]) -> list[str]:
        return sorted(self.dns[entry_id] for entry_id in ids)


def _ber_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("negative BER length")
    if length < 128:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _ber_tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _ber_length(len(content)) + content


def _ber_octets(value: str) -> bytes:
    return _ber_tlv(0x04, value.encode("utf-8"))


def _ber_integer(value: int, tag: int = 0x02) -> bytes:
    if value < 0:
        raise ValueError("only non-negative BER integers are used")
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _ber_tlv(tag, encoded)


def search_request_ber(
        filter_node: Filter, base_dn: str, attributes: Sequence[str]) -> bytes:
    request_content = b"".join((
        _ber_octets(base_dn),
        _ber_integer(2, tag=0x0A),       # subtree
        _ber_integer(0, tag=0x0A),       # never dereference aliases
        _ber_integer(0),                 # size limit
        _ber_integer(0),                 # time limit
        _ber_tlv(0x01, b"\x00"),       # typesOnly false
        filter_node.ber(),
        _ber_tlv(0x30, b"".join(_ber_octets(attr) for attr in attributes)),
    ))
    ldap_message = _ber_integer(1) + _ber_tlv(0x63, request_content)
    return _ber_tlv(0x30, ldap_message)
