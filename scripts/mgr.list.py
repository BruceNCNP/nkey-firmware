#!/usr/bin/env python3
"""List index_store rows, or a crypt store when a type is given.

    python scripts/mgr.list.py
    python scripts/mgr.list.py ssh
    python scripts/mgr.list.py passwd
    python scripts/mgr.list.py --self-test

Default (no type) reads index_store only. Pass ssh/passwd/otp/oath/fido to
read that crypt store instead. Listing does not ask for the button.

OpenSSH stores ``-O user`` in the credential user id. On the libfido2 path
that id is a 32-byte buffer, the text is at the front, and the rest is NUL.
``user.name`` and ``user.displayName`` are the fixed string ``openssh``, so
those fields are not the ``-O user`` value. Windows OpenSSH uses the same
user id, and the default when ``-O user`` is omitted is the text ``null``.
Columns are the row number, type, ``user.id``, ``user.name``, and
``user.displayName``. A 32-byte zero id prints as ``(none)``.

CTAP goes through the FIDO applet, instruction ``80 10``. The standard AID
is ``A0 00 00 06 47 2F 00 01``. Windows denies that AID, so the script then
selects the backup AID ``B0 00 00 06 47 2F 00 01``. Enumeration is sent
without pinUvAuth. Windows uses winscard.dll. Linux uses
libpcsclite.so.1. No extra packages.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import secrets
import sys
from ctypes import POINTER, byref, c_void_p
from dataclasses import dataclass

FIDO_AIDS = (
    bytes((0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01)),
    bytes((0xB0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01)),
)
PASSWD_AID = bytes((0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x22))
INDEX_AID = bytes((0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x23))
INDEX_CLA = 0x82
INDEX_INS = 0x30
INDEX_P1_PUT = 0x10
INDEX_P1_DEL = 0x20
INDEX_P1_LIST = 0x30
INDEX_P1_GET = 0x31
INDEX_TYPE_SSH = 0x01
INDEX_TYPE_PASSWD = 0x02
INDEX_TYPE_OTP = 0x03
INDEX_TYPE_OATH = 0x04
INDEX_TYPE_FIDO = 0x05
INDEX_RECORD_ID_LEN = 32
IX_TAG_USERNAME = 0x01
IX_TAG_IP = 0x02
IX_TAG_URL = 0x03
IX_TAG_ALIAS = 0x04
SW_OK = 0x9000
SCARD_SHARE_EXCLUSIVE = 1
SCARD_E_SHARING_VIOLATION = 0x8010000B
_CLA_REJECT = {
    1: "router",
    2: "passwd",
    3: "fido",
    4: "rescue",
    5: "otp",
    6: "oath",
    7: "management",
    8: "u2f",
    9: "index",
}
_INDEX_TYPE_NAME = {
    INDEX_TYPE_SSH: "ssh",
    INDEX_TYPE_PASSWD: "passwd",
    INDEX_TYPE_OTP: "otp",
    INDEX_TYPE_OATH: "oath",
    INDEX_TYPE_FIDO: "fido",
}
SCARD_E_NO_READERS_AVAILABLE = 0x8010002E
CTAP_CLIENT_PIN = 0x06
CTAP_CRED_MGMT = 0x0A
CTAP_NO_CREDENTIALS = 0x2E
PERMISSION_CM = 0x04
MAX_RECORDS = 256
OPENSSH_NAME = "openssh"

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

AES_SBOX = bytes((
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
))
AES_INV = bytes(AES_SBOX.index(i) for i in range(256))
AES_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


@dataclass
class Resident:
    rp_id: str
    user_id: bytes
    name: str
    display_name: str
    cred_id: bytes = b""


@dataclass
class PasswordSlot:
    slot: int
    name: str
    display_name: str
    ident: bytes = b""


@dataclass
class IndexEntry:
    slot: int
    entry_type: int
    record_id: bytes
    username: str = ""
    ip: str = ""
    url: str = ""
    aliases: list[str] | None = None

    def __post_init__(self) -> None:
        if self.aliases is None:
            self.aliases = []


class CtapError(Exception):
    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(_ctap_text(code))


def _ctap_text(code: int) -> str:
    known = {
        0x27: "The button was not pressed.",
        0x2C: "The board is not using button verification.",
        0x2E: "No resident credentials.",
        0x2F: "The button wait timed out.",
        0x30: "The board stopped listing records.",
        0x33: "The board rejected the list request.",
        0x36: "The board asked for a verification token.",
    }
    return known.get(code, f"The board returned CTAP error {code:#04x}.")


def format_user_id(raw: bytes) -> str:
    """``user.id`` for the id column.

    Drop only trailing NUL bytes. libfido2 writes text into a 32-byte id and
    fills the tail with NUL. An all-zero id means the field was omitted.
    """

    trimmed = raw.rstrip(b"\x00")
    if not trimmed:
        return "(none)"
    try:
        text = trimmed.decode("utf-8")
    except UnicodeDecodeError:
        return trimmed.hex()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return trimmed.hex()
    return text


def format_list(rows: list[Resident], slots: list[PasswordSlot] | None = None) -> str:
    slots = [] if slots is None else slots
    if not rows and not slots:
        return "No resident credentials.\n"
    records = [_record(index, row) for index, row in enumerate(rows, 1)]
    start = len(records) + 1
    records.extend(_password_record(index, slot) for index, slot in enumerate(slots, start))
    widths = _widths(records)
    lines = [_join(_HEADER, widths)]
    lines.extend(_join(record, widths) for record in records)
    return "\n".join(lines) + "\n"


_INDEX_HEADER = ("#", "type", "id", "username", "ip/url", "alias")


def format_index_list(entries: list[IndexEntry]) -> str:
    if not entries:
        return "No index entries.\n"
    records = []
    for index, entry in enumerate(entries, 1):
        kind = _INDEX_TYPE_NAME.get(entry.entry_type, f"0x{entry.entry_type:02x}")
        host = entry.ip or entry.url
        alias = " ".join(entry.aliases or [])
        records.append((str(index), kind, format_user_id(entry.record_id), entry.username, host, alias))
    widths = _widths(records)
    lines = [_join(_INDEX_HEADER, widths)]
    lines.extend(_join(record, widths) for record in records)
    return "\n".join(lines) + "\n"


def index_tlv_field(tag: int, value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("index TLV field is too long")
    return bytes((tag,)) + len(value).to_bytes(2, "big") + value


def build_index_tlv(
    username: str = "",
    ip: str = "",
    url: str = "",
    aliases: list[str] | None = None,
) -> bytes:
    body = b""
    if username:
        body += index_tlv_field(IX_TAG_USERNAME, username.encode("utf-8"))
    if ip:
        body += index_tlv_field(IX_TAG_IP, ip.encode("utf-8"))
    if url:
        body += index_tlv_field(IX_TAG_URL, url.encode("utf-8"))
    for alias in aliases or []:
        raw = alias.encode("utf-8")
        if len(raw) > 64:
            raise ValueError("alias is longer than 64 bytes")
        body += index_tlv_field(IX_TAG_ALIAS, raw)
    return body


def passwd_record_id(ident: bytes) -> bytes:
    if len(ident) != 8:
        raise ValueError("password id must be 8 bytes")
    return ident + bytes(INDEX_RECORD_ID_LEN - 8)


def parse_index_tlv(tlv: bytes) -> tuple[str, str, str, list[str]]:
    username = ""
    ip = ""
    url = ""
    aliases: list[str] = []
    pos = 0
    while pos < len(tlv):
        if pos + 3 > len(tlv):
            raise ValueError("truncated index TLV")
        tag = tlv[pos]
        flen = int.from_bytes(tlv[pos + 1:pos + 3], "big")
        pos += 3
        if pos + flen > len(tlv):
            raise ValueError("truncated index TLV value")
        value = tlv[pos:pos + flen]
        pos += flen
        if tag == IX_TAG_USERNAME:
            username = value.decode("utf-8", errors="replace")
        elif tag == IX_TAG_IP:
            ip = value.decode("utf-8", errors="replace")
        elif tag == IX_TAG_URL:
            url = value.decode("utf-8", errors="replace")
        elif tag == IX_TAG_ALIAS:
            aliases.append(value.decode("utf-8", errors="replace"))
    return username, ip, url, aliases


def parse_index_record(raw: bytes, slot: int) -> IndexEntry:
    if len(raw) < 38:
        raise ValueError("short index record")
    tlv_len = int.from_bytes(raw[36:38], "big")
    if 38 + tlv_len != len(raw):
        raise ValueError("index record length mismatch")
    username, ip, url, aliases = parse_index_tlv(raw[38:])
    return IndexEntry(
        slot=slot,
        entry_type=raw[1],
        record_id=raw[4:36],
        username=username,
        ip=ip,
        url=url,
        aliases=aliases,
    )


def index_apdu(p1: int, data: bytes = b"") -> bytes:
    return bytes((INDEX_CLA, INDEX_INS, p1, 0x00, len(data))) + data


def index_list_apdu(start: int) -> bytes:
    return index_apdu(INDEX_P1_LIST, start.to_bytes(2, "big"))


def index_put_apdu(entry_type: int, record_id: bytes, tlv: bytes) -> bytes:
    if len(record_id) != INDEX_RECORD_ID_LEN:
        raise ValueError("bad index record id")
    return index_apdu(INDEX_P1_PUT, bytes((entry_type,)) + record_id + tlv)


def index_del_apdu(entry_type: int, record_id: bytes) -> bytes:
    if len(record_id) != INDEX_RECORD_ID_LEN:
        raise ValueError("bad index record id")
    return index_apdu(INDEX_P1_DEL, bytes((entry_type,)) + record_id)


def select_index(pcsc: "Pcsc", card: int) -> None:
    body, status = transmit_all(pcsc, card, select_apdu(INDEX_AID))
    if status != SW_OK:
        raise OSError(f"Index applet rejected SELECT with {status_detail(body, status)}")


def list_index_entries(pcsc: "Pcsc", card: int) -> list[IndexEntry]:
    select_index(pcsc, card)
    entries: list[IndexEntry] = []
    start = 0
    for _ in range(512):
        body, status = transmit_all(pcsc, card, index_list_apdu(start))
        if status != SW_OK:
            raise OSError(f"Index list failed with {status_detail(body, status)}")
        if len(body) < 3:
            raise ValueError("short index list page")
        has_more = body[0]
        next_start = int.from_bytes(body[1:3], "big")
        pos = 3
        while pos < len(body):
            if pos + 2 > len(body):
                raise ValueError("truncated index list entry")
            slot = int.from_bytes(body[pos:pos + 2], "big")
            pos += 2
            if pos + 38 > len(body):
                raise ValueError("truncated index list record")
            tlv_len = int.from_bytes(body[pos + 36:pos + 38], "big")
            total = 38 + tlv_len
            if pos + total > len(body):
                raise ValueError("truncated index list payload")
            entries.append(parse_index_record(body[pos:pos + total], slot))
            pos += total
        if not has_more:
            return entries
        if next_start <= start:
            raise ValueError("The board repeated an index list page.")
        start = next_start
    raise ValueError("The board did not finish the index list.")


def put_index_entry(
    pcsc: "Pcsc",
    card: int,
    entry_type: int,
    record_id: bytes,
    tlv: bytes,
) -> None:
    select_index(pcsc, card)
    body, status = transmit_all(pcsc, card, index_put_apdu(entry_type, record_id, tlv))
    if status == 0x6985:
        raise OSError("The button was not pressed.")
    if status == 0x6A84:
        raise OSError("Index store is full.")
    if status != SW_OK:
        raise OSError(f"Index put failed with {status_detail(body, status)}")


def delete_index_entry(pcsc: "Pcsc", card: int, entry_type: int, record_id: bytes) -> None:
    select_index(pcsc, card)
    body, status = transmit_all(pcsc, card, index_del_apdu(entry_type, record_id))
    if status == 0x6985:
        raise OSError("The button was not pressed.")
    if status == 0x6A82:
        return
    if status != SW_OK:
        raise OSError(f"Index delete failed with {status_detail(body, status)}")


def _record(index: int, row: Resident) -> tuple[str, str, str, str, str]:
    kind = "ssh" if row.rp_id == "ssh:" else row.rp_id
    return (str(index), kind, format_user_id(row.user_id), row.name, row.display_name)


def _password_record(index: int, slot: PasswordSlot) -> tuple[str, str, str, str, str]:
    return (str(index), "passwd", format_user_id(slot.ident), slot.name, slot.display_name)


_HEADER = ("#", "type", "user.id", "user.name", "user.displayName")


def _widths(records: list[tuple[str, str, str, str, str]]) -> tuple[int, int, int, int, int]:
    columns = (_HEADER, *records)
    return (
        max(len(row[0]) for row in columns),
        max(len(row[1]) for row in columns),
        max(len(row[2]) for row in columns),
        max(len(row[3]) for row in columns),
        max(len(row[4]) for row in columns),
    )


def _join(fields: tuple[str, str, str, str, str], widths: tuple[int, int, int, int, int]) -> str:
    parts = [f"{fields[0]:>{widths[0]}}"]
    parts.extend(f"{field:<{width}}" for field, width in zip(fields[1:], widths[1:]))
    return "  ".join(parts).rstrip()


def parse_password_page(body: bytes) -> tuple[int, int, list[PasswordSlot]]:
    if len(body) < 5:
        raise ValueError("The board returned a short password list.")
    has_more = body[0]
    if has_more not in (0, 1):
        raise ValueError("The board returned a bad password list.")
    next_start = int.from_bytes(body[1:3], "big")
    count = int.from_bytes(body[3:5], "big")
    pos = 5
    slots: list[PasswordSlot] = []
    for _ in range(count):
        if pos + 11 > len(body):
            raise ValueError("The board returned a short password list.")
        slot = int.from_bytes(body[pos:pos + 2], "big")
        ident = body[pos + 2:pos + 10]
        name_len = body[pos + 10]
        pos += 11
        if pos + name_len + 1 > len(body):
            raise ValueError("The board returned a short password list.")
        name = body[pos:pos + name_len]
        pos += name_len
        display_len = body[pos]
        pos += 1
        if pos + display_len > len(body):
            raise ValueError("The board returned a short password list.")
        display = body[pos:pos + display_len]
        pos += display_len
        slots.append(PasswordSlot(slot, _utf8_field(name), _utf8_field(display), ident))
    if pos != len(body) or len(slots) != count:
        raise ValueError("The board returned a bad password list.")
    return has_more, next_start, slots


def _utf8_field(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("The board returned a bad password name.") from exc


def passwd_list_apdu(start: int) -> bytes:
    if start < 0 or start > 0xFFFF:
        raise ValueError("bad password list start")
    data = start.to_bytes(2, "big")
    return bytes((0x81, 0x22, 0x30, 0x00, 0x00, 0x00, 0x02)) + data + bytes((0x04, 0x00))


def _format_row(index: int, width: int, row: Resident) -> str:
    record = _record(index, row)
    widths = _widths([record])
    return _join(record, (max(width, widths[0]), *widths[1:]))


def cbor_decode(data: bytes, index: int = 0):
    if index >= len(data):
        raise ValueError("truncated CBOR")
    initial = data[index]
    major = initial >> 5
    info = initial & 0x1F
    index += 1
    if info < 24:
        argument = info
    elif info == 24:
        argument = data[index]
        index += 1
    elif info == 25:
        argument = int.from_bytes(data[index:index + 2], "big")
        index += 2
    elif info == 26:
        argument = int.from_bytes(data[index:index + 4], "big")
        index += 4
    elif info == 27:
        argument = int.from_bytes(data[index:index + 8], "big")
        index += 8
    else:
        raise ValueError("unsupported CBOR length")
    if index > len(data):
        raise ValueError("truncated CBOR")
    if major == 0:
        return argument, index
    if major == 1:
        return -1 - argument, index
    if major in (2, 3):
        end = index + argument
        if end > len(data):
            raise ValueError("truncated CBOR")
        blob = data[index:end]
        if major == 2:
            return blob, end
        return blob.decode("utf-8", "replace"), end
    if major == 4:
        items = []
        for _ in range(argument):
            item, index = cbor_decode(data, index)
            items.append(item)
        return items, index
    if major == 5:
        pairs = {}
        for _ in range(argument):
            key, index = cbor_decode(data, index)
            item, index = cbor_decode(data, index)
            pairs[key] = item
        return pairs, index
    if major == 6:
        return cbor_decode(data, index)
    if major == 7 and info == 20:
        return False, index
    if major == 7 and info == 21:
        return True, index
    if major == 7 and info == 22:
        return None, index
    raise ValueError("unsupported CBOR value")


def cbor_one(data: bytes):
    value, index = cbor_decode(data, 0)
    if index != len(data):
        raise ValueError("trailing CBOR")
    if not isinstance(value, dict):
        raise ValueError("CBOR map expected")
    return value


def _p256_affine(point: tuple[int, int, int] | None) -> tuple[int, int]:
    if point is None:
        raise ValueError("point at infinity")
    x_j, y_j, z_j = point
    if z_j == 0:
        raise ValueError("point at infinity")
    inv = pow(z_j, -1, P256_P)
    inv2 = (inv * inv) % P256_P
    return (x_j * inv2) % P256_P, (y_j * inv2 * inv) % P256_P


def _p256_on_curve(x_a: int, y_a: int) -> bool:
    return (y_a * y_a - (x_a * x_a * x_a + P256_A * x_a + P256_B)) % P256_P == 0


def _p256_double(point: tuple[int, int, int] | None) -> tuple[int, int, int] | None:
    if point is None:
        return None
    x_j, y_j, z_j = point
    if y_j == 0 or z_j == 0:
        return None
    delta = (z_j * z_j) % P256_P
    gamma = (y_j * y_j) % P256_P
    beta = (x_j * gamma) % P256_P
    alpha = (3 * (x_j - delta) * (x_j + delta)) % P256_P
    x3 = (alpha * alpha - 8 * beta) % P256_P
    z3 = (2 * y_j * z_j) % P256_P
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % P256_P
    return x3, y3, z3


def _p256_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1, z1 = left
    x2, y2, z2 = right
    z1z1 = (z1 * z1) % P256_P
    z2z2 = (z2 * z2) % P256_P
    u1 = (x1 * z2z2) % P256_P
    u2 = (x2 * z1z1) % P256_P
    s1 = (y1 * z2 * z2z2) % P256_P
    s2 = (y2 * z1 * z1z1) % P256_P
    if u1 == u2:
        if s1 != s2:
            return None
        return _p256_double(left)
    height = (u2 - u1) % P256_P
    rise = (s2 - s1) % P256_P
    hh = (height * height) % P256_P
    hhh = (height * hh) % P256_P
    v_coord = (u1 * hh) % P256_P
    x3 = (rise * rise - hhh - 2 * v_coord) % P256_P
    y3 = (rise * (v_coord - x3) - s1 * hhh) % P256_P
    z3 = (z1 * z2 * height) % P256_P
    return x3, y3, z3


def _p256_mul(scalar: int, point):
    if point is None or scalar % P256_N == 0:
        return None
    result = None
    addend = point
    k = scalar
    while k:
        if k & 1:
            result = _p256_add(result, addend)
        addend = _p256_double(addend)
        k >>= 1
    return result


def _i32(value: int) -> bytes:
    return value.to_bytes(32, "big")


def platform_key() -> tuple[int, bytes]:
    scalar = secrets.randbelow(P256_N - 1) + 1
    x_a, y_a = _p256_affine(_p256_mul(scalar, (P256_GX, P256_GY, 1)))
    cose = bytes((0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20))
    cose += _i32(x_a) + bytes((0x22, 0x58, 0x20)) + _i32(y_a)
    return scalar, cose


def shared_secret(scalar: int, x_bytes: bytes, y_bytes: bytes) -> bytes:
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("bad agreement key")
    x_a = int.from_bytes(x_bytes, "big")
    y_a = int.from_bytes(y_bytes, "big")
    if not _p256_on_curve(x_a, y_a):
        raise ValueError("bad agreement key")
    point = _p256_mul(scalar, (x_a, y_a, 1))
    shared_x, _shared_y = _p256_affine(point)
    return hashlib.sha256(_i32(shared_x)).digest()


def _xtime(value: int) -> int:
    return ((value << 1) ^ 0x1B) & 0xFF if value & 0x80 else (value << 1) & 0xFF


def _aes_mul(left: int, right: int) -> int:
    result = 0
    while right:
        if right & 1:
            result ^= left
        left = _xtime(left)
        right >>= 1
    return result


def _sub_word(word: int) -> int:
    return (
        (AES_SBOX[(word >> 24) & 0xFF] << 24)
        | (AES_SBOX[(word >> 16) & 0xFF] << 16)
        | (AES_SBOX[(word >> 8) & 0xFF] << 8)
        | AES_SBOX[word & 0xFF]
    )


def _expand_aes256(key: bytes) -> list[bytes]:
    words = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(8)]
    for index in range(8, 60):
        temp = words[index - 1]
        if index % 8 == 0:
            rotated = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            temp = _sub_word(rotated) ^ (AES_RCON[index // 8] << 24)
        elif index % 8 == 4:
            temp = _sub_word(temp)
        words.append(words[index - 8] ^ temp)
    rounds = []
    for round_index in range(15):
        chunk = words[4 * round_index:4 * round_index + 4]
        rounds.append(b"".join(word.to_bytes(4, "big") for word in chunk))
    return rounds


def _add_round_key(state: bytearray, round_key: bytes) -> None:
    for index, byte in enumerate(round_key):
        state[index] ^= byte


def _inv_shift_rows(state: bytearray) -> None:
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def _inv_sub_bytes(state: bytearray) -> None:
    for index, byte in enumerate(state):
        state[index] = AES_INV[byte]


def _inv_mix_columns(state: bytearray) -> None:
    for col in range(4):
        index = 4 * col
        a0, a1, a2, a3 = state[index:index + 4]
        state[index] = _aes_mul(a0, 0x0E) ^ _aes_mul(a1, 0x0B) ^ _aes_mul(a2, 0x0D) ^ _aes_mul(a3, 0x09)
        state[index + 1] = _aes_mul(a0, 0x09) ^ _aes_mul(a1, 0x0E) ^ _aes_mul(a2, 0x0B) ^ _aes_mul(a3, 0x0D)
        state[index + 2] = _aes_mul(a0, 0x0D) ^ _aes_mul(a1, 0x09) ^ _aes_mul(a2, 0x0E) ^ _aes_mul(a3, 0x0B)
        state[index + 3] = _aes_mul(a0, 0x0B) ^ _aes_mul(a1, 0x0D) ^ _aes_mul(a2, 0x09) ^ _aes_mul(a3, 0x0E)


def _decrypt_block(block: bytes, rounds: list[bytes]) -> bytes:
    state = bytearray(block)
    _add_round_key(state, rounds[14])
    for round_index in range(13, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, rounds[round_index])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, rounds[0])
    return bytes(state)


def aes256_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != 32 or len(iv) != 16 or len(data) == 0 or len(data) % 16:
        raise ValueError("bad AES input")
    rounds = _expand_aes256(key)
    out = bytearray()
    previous = iv
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        plain = _decrypt_block(block, rounds)
        out.extend(left ^ right for left, right in zip(plain, previous))
        previous = block
    return bytes(out)


def hmac16(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()[:16]


def decrypt_token(key: bytes, cipher: bytes) -> bytes:
    if len(cipher) != 32:
        raise ValueError("bad verification token")
    return aes256_cbc_decrypt(key, bytes(16), cipher)


def _with_cmd(command: int, body: bytes) -> bytes:
    return bytes((command,)) + body


def _cose_xy(cose: dict) -> tuple[bytes, bytes]:
    x_bytes = cose.get(-2)
    y_bytes = cose.get(-3)
    if not isinstance(x_bytes, bytes) or not isinstance(y_bytes, bytes):
        raise ValueError("The board returned a bad agreement key.")
    return x_bytes, y_bytes


def _uv_request(cose: bytes, auth: bytes) -> bytes:
    return bytes((0xA5, 0x01, 0x01, 0x02, 0x06, 0x03)) + cose + bytes((0x04, 0x50)) + auth + bytes((0x09, PERMISSION_CM))


def _enum_rps(auth: bytes | None = None) -> bytes:
    if auth is None:
        return bytes((0xA1, 0x01, 0x02))
    return bytes((0xA3, 0x01, 0x02, 0x03, 0x01, 0x04, 0x50)) + auth


def _cred_params(rp_hash: bytes) -> bytes:
    return bytes((0xA1, 0x01, 0x58, 0x20)) + rp_hash


def _enum_creds(params: bytes, auth: bytes | None = None) -> bytes:
    if auth is None:
        return bytes((0xA2, 0x01, 0x04, 0x02)) + params
    return bytes((0xA4, 0x01, 0x04, 0x02)) + params + bytes((0x03, 0x01, 0x04, 0x50)) + auth


def _user_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return b""


def _text_field(user: dict, key: str) -> str:
    value = user.get(key, "")
    return value if isinstance(value, str) else ""


def parse_rp(body: bytes) -> tuple[str, bytes, int | None]:
    value = cbor_one(body)
    party = value.get(0x03)
    rp_hash = value.get(0x04)
    if not isinstance(party, dict) or not isinstance(party.get("id"), str) or not isinstance(rp_hash, bytes):
        raise ValueError("The board returned a bad relying party.")
    total = value.get(0x05)
    if total is not None and not isinstance(total, int):
        raise ValueError("The board returned a bad relying party.")
    return party["id"], rp_hash, total


def parse_cred(body: bytes) -> tuple[Resident, int | None]:
    value = cbor_one(body)
    user = value.get(0x06)
    if not isinstance(user, dict):
        raise ValueError("The board returned a bad credential.")
    total = value.get(0x09)
    if total is not None and not isinstance(total, int):
        raise ValueError("The board returned a bad credential.")
    resident = Resident(
        rp_id="",
        user_id=_user_bytes(user.get("id", b"")),
        name=_text_field(user, "name"),
        display_name=_text_field(user, "displayName"),
        cred_id=_descriptor_id(value.get(0x07)),
    )
    return resident, total


def _descriptor_id(descriptor) -> bytes:
    if not isinstance(descriptor, dict):
        return b""
    return _user_bytes(descriptor.get("id", b""))


def check_total(total: int) -> None:
    if total < 1 or total > MAX_RECORDS:
        raise ValueError("The board reported too many records.")


class Pcsc:
    def __init__(self) -> None:
        if sys.platform == "win32":
            self._lib = ctypes.WinDLL("winscard")
            self._dword = ctypes.c_uint32
            self._context = ctypes.c_void_p
            self._unicode = True
        else:
            self._lib = ctypes.CDLL("libpcsclite.so.1")
            self._dword = ctypes.c_ulong
            self._context = ctypes.c_long
            self._unicode = False
        self._bind()
        self._pci = ctypes.cast(
            ctypes.addressof(ctypes.c_char.in_dll(self._lib, "g_rgSCardT1Pci")),
            c_void_p,
        )

    def _bind(self) -> None:
        dword = self._dword
        context = self._context
        handle = context
        lib = self._lib
        lib.SCardEstablishContext.argtypes = [dword, c_void_p, c_void_p, POINTER(context)]
        lib.SCardEstablishContext.restype = ctypes.c_long
        lib.SCardReleaseContext.argtypes = [context]
        lib.SCardReleaseContext.restype = ctypes.c_long
        lib.SCardDisconnect.argtypes = [handle, dword]
        lib.SCardDisconnect.restype = ctypes.c_long
        lib.SCardTransmit.argtypes = [
            handle,
            c_void_p,
            POINTER(ctypes.c_ubyte),
            dword,
            c_void_p,
            POINTER(ctypes.c_ubyte),
            POINTER(dword),
        ]
        lib.SCardTransmit.restype = ctypes.c_long
        if self._unicode:
            reader_fn = lib.SCardListReadersW
            connect_fn = lib.SCardConnectW
            char_p = ctypes.c_wchar_p
        else:
            reader_fn = lib.SCardListReaders
            connect_fn = lib.SCardConnect
            char_p = ctypes.c_char_p
        reader_fn.argtypes = [context, char_p, c_void_p, POINTER(dword)]
        reader_fn.restype = ctypes.c_long
        connect_fn.argtypes = [context, char_p, dword, dword, POINTER(handle), POINTER(dword)]
        connect_fn.restype = ctypes.c_long
        self._list = reader_fn
        self._connect = connect_fn

    def establish(self) -> int:
        ctx = self._context()
        code = self._lib.SCardEstablishContext(0, None, None, byref(ctx))
        if code != 0:
            raise OSError(f"PC/SC is unavailable: 0x{code & 0xFFFFFFFF:08X}")
        return ctx.value

    def release(self, context: int) -> None:
        self._lib.SCardReleaseContext(self._context(context))

    def readers(self, context: int) -> list[str]:
        count = self._dword(0)
        code = self._list(self._context(context), None, None, byref(count))
        if (code & 0xFFFFFFFF) == SCARD_E_NO_READERS_AVAILABLE:
            return []
        if code != 0:
            raise OSError(f"SCardListReaders size failed: 0x{code & 0xFFFFFFFF:08X}")
        if count.value == 0:
            return []
        if self._unicode:
            buffer = ctypes.create_unicode_buffer(count.value)
        else:
            buffer = ctypes.create_string_buffer(count.value)
        code = self._list(self._context(context), None, ctypes.cast(buffer, c_void_p), byref(count))
        if (code & 0xFFFFFFFF) == SCARD_E_NO_READERS_AVAILABLE:
            return []
        if code != 0:
            raise OSError(f"SCardListReaders failed: 0x{code & 0xFFFFFFFF:08X}")
        if self._unicode:
            text = ctypes.wstring_at(ctypes.addressof(buffer), count.value)
            return [name for name in text.split("\x00") if name]
        return [name.decode("utf-8", "replace") for name in buffer.raw.split(b"\x00") if name]

    def connect(self, context: int, reader: str) -> int | None:
        card = self._context()
        protocol = self._dword()
        name = reader if self._unicode else reader.encode("utf-8")
        code = self._connect(self._context(context), name, SCARD_SHARE_EXCLUSIVE, 3, byref(card), byref(protocol))
        if (code & 0xFFFFFFFF) == SCARD_E_SHARING_VIOLATION:
            raise OSError("The board is in use by another program.")
        if code != 0:
            return None
        return card.value

    def disconnect(self, card: int) -> None:
        self._lib.SCardDisconnect(self._context(card), 0)

    def transmit(self, card: int, apdu: bytes) -> tuple[bytes, int]:
        send = (ctypes.c_ubyte * len(apdu))(*apdu)
        recv = (ctypes.c_ubyte * 4096)()
        recv_len = self._dword(len(recv))
        code = self._lib.SCardTransmit(
            self._context(card),
            self._pci,
            send,
            self._dword(len(apdu)),
            None,
            recv,
            byref(recv_len),
        )
        if code != 0:
            raise OSError(f"SCardTransmit failed: 0x{code & 0xFFFFFFFF:08X}")
        size = int(recv_len.value)
        if size < 2:
            raise OSError("card response is shorter than a status word")
        payload = bytes(recv[:size])
        status = (payload[-2] << 8) | payload[-1]
        return payload[:-2], status


def ctap_apdu(payload: bytes) -> bytes:
    if len(payload) > 65535:
        raise ValueError("CTAP payload is too long")
    length = len(payload)
    return bytes((0x80, 0x10, 0x00, 0x00, 0x00, length >> 8, length & 0xFF)) + payload + b"\x00\x00"


def _get_response(le: int) -> bytes:
    if le <= 0 or le > 65536:
        le = 256
    if le == 65536:
        return bytes((0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00))
    if le == 256:
        return bytes((0x00, 0xC0, 0x00, 0x00, 0x00))
    if le < 256:
        return bytes((0x00, 0xC0, 0x00, 0x00, le))
    return bytes((0x00, 0xC0, 0x00, 0x00, 0x00, le >> 8, le & 0xFF))


def transmit_all(pcsc: Pcsc, card: int, apdu: bytes) -> tuple[bytes, int]:
    body, status = pcsc.transmit(card, apdu)
    parts = [body]
    for _ in range(16):
        if (status & 0xFF00) != 0x6100:
            break
        remaining = status & 0xFF
        more, status = pcsc.transmit(card, _get_response(256 if remaining == 0 else remaining))
        parts.append(more)
    return b"".join(parts), status


def find_fido(pcsc: Pcsc) -> tuple[tuple[int, int, str] | None, bool]:
    return _find_reader(pcsc, lambda card: _select_fido(pcsc, card))


def find_nkey(pcsc: Pcsc) -> tuple[tuple[int, int, str] | None, bool]:
    def selected(card: int) -> bool:
        return _select_fido(pcsc, card) or _select_aid(pcsc, card, PASSWD_AID)

    return _find_reader(pcsc, selected)


def find_passwd(pcsc: Pcsc) -> tuple[tuple[int, int, str] | None, bool]:
    def selected(card: int) -> bool:
        return _select_aid(pcsc, card, PASSWD_AID)

    return _find_reader(pcsc, selected)


def _find_reader(pcsc: Pcsc, selected) -> tuple[tuple[int, int, str] | None, bool]:
    context = pcsc.establish()
    try:
        names = pcsc.readers(context)
    except OSError:
        pcsc.release(context)
        raise
    if not names:
        pcsc.release(context)
        return None, False
    for reader in names:
        card = pcsc.connect(context, reader)
        if card is None:
            continue
        if selected(card):
            return (context, card, reader), True
        pcsc.disconnect(card)
    pcsc.release(context)
    return None, True


def select_apdu(aid: bytes) -> bytes:
    return bytes((0x00, 0xA4, 0x04, 0x00, len(aid))) + aid + bytes((0x00,))


def _select_aid(pcsc: Pcsc, card: int, aid: bytes) -> bool:
    try:
        _body, status = pcsc.transmit(card, select_apdu(aid))
    except OSError:
        return False
    return status == SW_OK


def _select_fido(pcsc: Pcsc, card: int) -> bool:
    for aid in FIDO_AIDS:
        if _select_aid(pcsc, card, aid):
            return True
    return False


def maintenance_seconds(pcsc: Pcsc, card: int, reselect_fido: bool = False) -> int:
    seconds = 0
    try:
        _body, status = transmit_all(pcsc, card, select_apdu(PASSWD_AID))
        if status == SW_OK:
            body, status = transmit_all(pcsc, card, bytes((0x81, 0x22, 0x42, 0x00, 0x00)))
            if status == SW_OK and len(body) == 2:
                seconds = int.from_bytes(body, "big")
    except OSError:
        seconds = 0
    if reselect_fido:
        _select_fido(pcsc, card)
    return seconds


def ask_button(pcsc: Pcsc, card: int, reselect_fido: bool = False) -> None:
    if maintenance_seconds(pcsc, card, reselect_fido=reselect_fido) > 0:
        return
    print("Press the button when the LED blinks blue.")
    sys.stdout.flush()


def close_session(pcsc: Pcsc, session: tuple[int, int, str] | None) -> None:
    if session is None:
        return
    context, card, _reader = session
    pcsc.disconnect(card)
    pcsc.release(context)


def ctap(pcsc: Pcsc, card: int, payload: bytes) -> bytes | None:
    body, status = transmit_all(pcsc, card, ctap_apdu(payload))
    if status == SW_OK:
        if not body or body[0] != 0x00:
            code = body[0] if body else 0x7F
            raise CtapError(code)
        return body[1:]
    if (status & 0xFF00) == 0x6400:
        code = status & 0xFF
        if code == CTAP_NO_CREDENTIALS:
            return None
        raise CtapError(code)
    raise OSError(f"FIDO applet rejected CTAP with SW {status:04X}")


def _agreement_point(body: bytes) -> tuple[bytes, bytes]:
    value = cbor_one(body)
    cose = value.get(1)
    if not isinstance(cose, dict):
        raise ValueError("The board returned a bad agreement key.")
    return _cose_xy(cose)


def _token_cipher(body: bytes) -> bytes:
    value = cbor_one(body)
    cipher = value.get(2)
    if not isinstance(cipher, bytes):
        raise ValueError("The board returned a bad verification token.")
    return cipher


def enumerate_credentials(pcsc: Pcsc, card: int, token: bytes | None = None) -> list[Resident]:
    auth = None if token is None else hmac16(token, b"\x02")
    first = ctap(pcsc, card, _with_cmd(CTAP_CRED_MGMT, _enum_rps(auth)))
    if first is None:
        return []
    rp_id, rp_hash, total = parse_rp(first)
    parties = [(rp_id, rp_hash)]
    rp_total = 1 if total is None else total
    check_total(rp_total)
    for _ in range(1, rp_total):
        nxt = ctap(pcsc, card, _with_cmd(CTAP_CRED_MGMT, b"\xA1\x01\x03"))
        if nxt is None:
            raise CtapError(0x30)
        rp_id, rp_hash, _total = parse_rp(nxt)
        parties.append((rp_id, rp_hash))

    rows: list[Resident] = []
    for party_id, party_hash in parties:
        if len(party_hash) != 32:
            raise ValueError("The board returned a bad relying party.")
        params = _cred_params(party_hash)
        auth = None if token is None else hmac16(token, b"\x04" + params)
        first = ctap(pcsc, card, _with_cmd(CTAP_CRED_MGMT, _enum_creds(params, auth)))
        if first is None:
            continue
        cred, total = parse_cred(first)
        cred.rp_id = party_id
        cred_total = 1 if total is None else total
        check_total(cred_total)
        rows.append(cred)
        for _ in range(1, cred_total):
            nxt = ctap(pcsc, card, _with_cmd(CTAP_CRED_MGMT, b"\xA1\x01\x05"))
            if nxt is None:
                raise CtapError(0x30)
            cred, _total = parse_cred(nxt)
            cred.rp_id = party_id
            rows.append(cred)
    return rows


def call_with_token(pcsc: Pcsc, session: tuple[int, int, str], action):
    _context, card, reader = session
    print(f"FIDO applet on {reader}")
    agreement = ctap(pcsc, card, _with_cmd(CTAP_CLIENT_PIN, b"\xA2\x01\x01\x02\x02"))
    if agreement is None:
        raise CtapError(0x2C)
    device_x, device_y = _agreement_point(agreement)
    scalar, cose = platform_key()
    secret = bytearray(shared_secret(scalar, device_x, device_y))
    auth = hmac16(secret, bytes((0x01, 0x06, PERMISSION_CM)))
    ask_button(pcsc, card, reselect_fido=True)
    token_body = ctap(pcsc, card, _with_cmd(CTAP_CLIENT_PIN, _uv_request(cose, auth)))
    if token_body is None:
        raise CtapError(0x2C)
    token = bytearray(decrypt_token(secret, _token_cipher(token_body)))
    secret[:] = b"\x00" * len(secret)
    try:
        return action(bytes(token))
    finally:
        token[:] = b"\x00" * len(token)


def status_detail(body: bytes, status: int) -> str:
    text = f"SW {status:04X}"
    if status == 0x6E00 and len(body) >= 13:
        why, cla, ins, p1, p2 = body[:5]
        mark_r = int.from_bytes(body[5:7], "big")
        mark_w = int.from_bytes(body[7:9], "big")
        now_r = int.from_bytes(body[9:11], "big")
        now_w = int.from_bytes(body[11:13], "big")
        where = _CLA_REJECT.get(why, str(why))
        text += (
            f" cla={cla:02X} ins={ins:02X} p1={p1:02X} p2={p2:02X}"
            f" where={where} rx@dispatch {mark_r}/{mark_w} rx@read {now_r}/{now_w}"
        )
    elif body:
        text += f" data {body.hex()}"
    return text


def list_password_slots(pcsc: Pcsc, card: int) -> list[PasswordSlot]:
    _body, status = transmit_all(pcsc, card, select_apdu(PASSWD_AID))
    if status != SW_OK:
        raise OSError(f"Password applet rejected SELECT with {status_detail(_body, status)}")
    slots: list[PasswordSlot] = []
    start = 0
    for _ in range(64):
        body, status = transmit_all(pcsc, card, passwd_list_apdu(start))
        if status != SW_OK:
            raise OSError(f"Password list failed with {status_detail(body, status)}")
        has_more, next_start, page = parse_password_page(body)
        slots.extend(page)
        if not has_more:
            return slots
        if next_start <= start:
            raise ValueError("The board repeated a password list page.")
        start = next_start
    raise ValueError("The board did not finish the password list.")


def list_resident(pcsc: Pcsc, session: tuple[int, int, str]) -> list[Resident]:
    _context, card, reader = session
    print(f"FIDO applet on {reader}")
    return enumerate_credentials(pcsc, card)


def run_index() -> int:
    pcsc = Pcsc()
    session, saw_reader = find_nkey(pcsc)
    if session is None:
        if saw_reader:
            print("The board did not answer.")
        else:
            print("Insert the nkey board.")
        return 1
    _context, card, reader = session
    try:
        print(f"Index applet on {reader}")
        entries = list_index_entries(pcsc, card)
    except OSError as exc:
        print(f"Index list failed: {exc}")
        print("If this board has older credentials without index rows, rebuild the index.")
        return 1
    finally:
        close_session(pcsc, session)
    sys.stdout.write(format_index_list(entries))
    sys.stdout.flush()
    return 0


def run_typed(kind: str) -> int:
    pcsc = Pcsc()
    session, saw_reader = find_nkey(pcsc)
    if session is None:
        if saw_reader:
            print("The board did not answer.")
        else:
            print("Insert the nkey board.")
        return 1
    _context, card, reader = session
    try:
        if kind == "ssh":
            if not _select_fido(pcsc, card):
                print("The FIDO applet did not answer.")
                return 1
            print(f"FIDO applet on {reader}")
            rows = [row for row in enumerate_credentials(pcsc, card) if row.rp_id == "ssh:"]
            sys.stdout.write(format_list(rows, []))
        elif kind == "passwd":
            print(f"Password applet on {reader}")
            slots = list_password_slots(pcsc, card)
            sys.stdout.write(format_list([], slots))
        elif kind in ("otp", "oath"):
            print(f"{kind} list is not implemented yet.")
            return 1
        elif kind == "fido":
            if not _select_fido(pcsc, card):
                print("The FIDO applet did not answer.")
                return 1
            print(f"FIDO applet on {reader}")
            rows = [row for row in enumerate_credentials(pcsc, card) if row.rp_id != "ssh:"]
            sys.stdout.write(format_list(rows, []))
        else:
            print(f"Unknown type {kind!r}. Use ssh, passwd, otp, oath, or fido.")
            return 1
    finally:
        close_session(pcsc, session)
    sys.stdout.flush()
    return 0


def run() -> int:
    return run_index()


def _affine_double(x_a: int, y_a: int) -> tuple[int, int]:
    slope = ((3 * x_a * x_a + P256_A) * pow(2 * y_a, -1, P256_P)) % P256_P
    x3 = (slope * slope - 2 * x_a) % P256_P
    y3 = (slope * (x_a - x3) - y_a) % P256_P
    return x3, y3


def self_test() -> int:
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cipher = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    if aes256_cbc_decrypt(key, iv, cipher) != plain:
        raise AssertionError("AES-256-CBC")
    detail = status_detail(bytes((2, 0x81, 0x22, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x00, 0x40)), 0x6E00)
    if detail != "SW 6E00 cla=81 ins=22 p1=10 p2=00 where=passwd rx@dispatch 0/0 rx@read 86/64":
        raise AssertionError(detail)
    if status_detail(b"", 0x6982) != "SW 6982":
        raise AssertionError("status without data")
    token_plain = b"\x9a" * 32
    token_cipher = _encrypt_zero_iv_for_test(b"\x03" * 32, token_plain)
    if decrypt_token(b"\x03" * 32, token_cipher) != token_plain:
        raise AssertionError("token decrypt")

    once = _p256_affine(_p256_mul(1, (P256_GX, P256_GY, 1)))
    if once != (P256_GX, P256_GY):
        raise AssertionError("P-256 generator")
    if _p256_mul(P256_N, (P256_GX, P256_GY, 1)) is not None:
        raise AssertionError("P-256 order")
    doubled = _p256_affine(_p256_mul(2, (P256_GX, P256_GY, 1)))
    if doubled != _affine_double(P256_GX, P256_GY):
        raise AssertionError("P-256 double")
    left = shared_secret(3, *_point_bytes(5))
    right = shared_secret(5, *_point_bytes(3))
    if left != right or len(left) != 32:
        raise AssertionError("P-256 shared secret")

    padded = b"alice" + b"\x00" * 27
    if format_user_id(padded) != "alice":
        raise AssertionError("padded -O user")
    if format_user_id(b"null") != "null":
        raise AssertionError("default user id null")
    if format_user_id(b"\x00" * 32) != "(none)":
        raise AssertionError("omitted -O user")

    cred_body = (
        bytes((0xA2, 0x06, 0xA2, 0x62, 0x69, 0x64, 0x58, 0x20))
        + padded
        + bytes((0x64, 0x6E, 0x61, 0x6D, 0x65, 0x67))
        + b"openssh"
        + bytes((0x09, 0x01))
    )
    cred, total = parse_cred(cred_body)
    cred.rp_id = "ssh:"
    if format_user_id(cred.user_id) != "alice" or total != 1:
        raise AssertionError("credential user id")
    text = format_list([cred, Resident("ssh:", b"null", OPENSSH_NAME, "qnas")])
    expected = (
        "#  type  user.id  user.name  user.displayName\n"
        "1  ssh   alice    openssh\n"
        "2  ssh   null     openssh    qnas\n"
    )
    if text != expected:
        raise AssertionError(f"list text {text!r}")
    omitted = Resident("ssh:", b"\x00" * 32, OPENSSH_NAME, OPENSSH_NAME)
    named = Resident("example.com", b"\x00" * 32, "bank", "")
    mixed = format_list([omitted, named])
    if "name=" in mixed or "display=" in mixed or "(none)" not in mixed or "bank" not in mixed:
        raise AssertionError(f"extra name {mixed!r}")
    if format_list([]) != "No resident credentials.\n":
        raise AssertionError("empty list")
    page = bytes((
        0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x03,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x06,
    )) + b"github" + bytes((0x04,)) + b"work"
    has_more, next_start, slots = parse_password_page(page)
    if has_more != 0 or next_start != 0 or len(slots) != 1:
        raise AssertionError("password page header")
    if slots[0].slot != 3 or slots[0].name != "github" or slots[0].display_name != "work":
        raise AssertionError("password page fields")
    if slots[0].ident != bytes((0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)):
        raise AssertionError("password id")
    mixed_rows = format_list([cred], slots)
    if mixed_rows != (
        "#  type    user.id           user.name  user.displayName\n"
        "1  ssh     alice             openssh\n"
        "2  passwd  1122334455667788  github     work\n"
    ):
        raise AssertionError(f"mixed list {mixed_rows!r}")
    if format_list([cred], []) != format_list([cred]):
        raise AssertionError("empty password rows changed the credential list")
    if passwd_list_apdu(0) != bytes((0x81, 0x22, 0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00)):
        raise AssertionError("password list APDU")
    if _enum_rps() != bytes((0xA1, 0x01, 0x02)):
        raise AssertionError("list rps without a button")
    cred_params = _cred_params(b"\x11" * 32)
    if _enum_creds(cred_params) != bytes((0xA2, 0x01, 0x04, 0x02)) + cred_params:
        raise AssertionError("list creds without a button")
    if _uv_request(b"\x11" * 4, b"\x22" * 16)[:6] != bytes((0xA5, 0x01, 0x01, 0x02, 0x06, 0x03)):
        raise AssertionError("uv request")
    standard = bytes((0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00))
    backup = bytes((0x00, 0xA4, 0x04, 0x00, 0x08, 0xB0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00))
    if select_apdu(FIDO_AIDS[0]) != standard or select_apdu(FIDO_AIDS[1]) != backup:
        raise AssertionError("select APDU")
    print("self-test ok")
    return 0


def _point_bytes(scalar: int) -> tuple[bytes, bytes]:
    x_a, y_a = _p256_affine(_p256_mul(scalar, (P256_GX, P256_GY, 1)))
    return _i32(x_a), _i32(y_a)


def _encrypt_zero_iv_for_test(key: bytes, plain: bytes) -> bytes:
    rounds = _expand_aes256(key)
    out = bytearray()
    previous = bytes(16)
    for offset in range(0, len(plain), 16):
        mixed = bytes(left ^ right for left, right in zip(plain[offset:offset + 16], previous))
        block = _encrypt_block(mixed, rounds)
        out.extend(block)
        previous = block
    return bytes(out)


def _encrypt_block(block: bytes, rounds: list[bytes]) -> bytes:
    state = bytearray(block)
    _add_round_key(state, rounds[0])
    for round_index in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, rounds[round_index])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, rounds[14])
    return bytes(state)


def _sub_bytes(state: bytearray) -> None:
    for index, byte in enumerate(state):
        state[index] = AES_SBOX[byte]


def _shift_rows(state: bytearray) -> None:
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _mix_columns(state: bytearray) -> None:
    for col in range(4):
        index = 4 * col
        a0, a1, a2, a3 = state[index:index + 4]
        state[index] = _aes_mul(a0, 2) ^ _aes_mul(a1, 3) ^ a2 ^ a3
        state[index + 1] = a0 ^ _aes_mul(a1, 2) ^ _aes_mul(a2, 3) ^ a3
        state[index + 2] = a0 ^ a1 ^ _aes_mul(a2, 2) ^ _aes_mul(a3, 3)
        state[index + 3] = _aes_mul(a0, 3) ^ a1 ^ a2 ^ _aes_mul(a3, 2)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "List index_store rows by default. Pass ssh/passwd/otp/oath/fido to read "
            "the matching crypt store instead."
        )
    )
    parser.add_argument("type", nargs="?", help="optional crypt-store type filter")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.self_test:
        return self_test()
    try:
        if args.type:
            return run_typed(args.type.lower())
        return run_index()
    except Exception as exc:
        print(f"List failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
