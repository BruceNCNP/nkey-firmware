#!/usr/bin/env python3
"""Store one password slot on the nkey board.

    python scripts/mgr.add.passwd.py secret github work
    python scripts/mgr.add.passwd.py --self-test

Three arguments are required: password, name, and displayname. The
password is ASCII the keyboard can type, from 1 to 254 bytes. name and
displayname are UTF-8 and may be empty. The first free slot is used.
Press the button when the LED blinks blue. A timeout does not store
the password. The list shows the name and displayname, not the secret.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import secrets
import sys
from pathlib import Path

INFO = b"nkey-passwd-v1-aes256gcm"
PLAIN_MAX = 512
PASSWORD_MAX = 254


def load_list():
    path = Path(__file__).with_name("mgr.list.py")
    spec = importlib.util.spec_from_file_location("mgr_list", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["mgr_list"] = module
    spec.loader.exec_module(module)
    return module


mgr = load_list()


def _control_free(label: str, text: str) -> bytes:
    raw = text.encode("utf-8")
    if len(raw) > 255:
        raise ValueError(f"{label} is longer than 255 bytes.")
    if any(byte <= 0x1F for byte in raw):
        raise ValueError(f"{label} contains a control character.")
    return raw


def check_fields(password: str, name: str, displayname: str) -> None:
    try:
        raw = password.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Password must be ASCII the keyboard can type.") from exc
    if not raw or len(raw) > PASSWORD_MAX:
        raise ValueError("Password must be 1 to 254 ASCII bytes.")
    name_raw = _control_free("name", name)
    display_raw = _control_free("displayname", displayname)
    if 16 + len(name_raw) + len(display_raw) + len(raw) > PLAIN_MAX:
        raise ValueError("name, displayname, and password are longer than 512 bytes together.")


def slot_plain(ident: bytes, name: str, displayname: str, password: str) -> bytes:
    if len(ident) != 8:
        raise ValueError("bad password id")
    name_raw = _control_free("name", name)
    display_raw = _control_free("displayname", displayname)
    secret = password.encode("ascii")
    body = bytes((0x01, 0x08)) + ident
    body += bytes((0x02, len(name_raw))) + name_raw
    body += bytes((0x03, len(display_raw))) + display_raw
    body += bytes((0x04, len(secret))) + secret
    if len(body) > PLAIN_MAX:
        raise ValueError("name, displayname, and password are longer than 512 bytes together.")
    return body


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes((counter,)), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _gf_mul(left: int, right: int) -> int:
    residue = 0xE1000000000000000000000000000000
    result = 0
    value = left
    for bit in range(128):
        if (right >> (127 - bit)) & 1:
            result ^= value
        if value & 1:
            value = (value >> 1) ^ residue
        else:
            value >>= 1
    return result


def _ghash(table: int, aad: bytes, ciphertext: bytes) -> int:
    state = 0
    for block in _padded_blocks(aad) + _padded_blocks(ciphertext):
        state = _gf_mul(state ^ block, table)
    lengths = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    return _gf_mul(state ^ lengths, table)


def _padded_blocks(data: bytes) -> list[int]:
    blocks = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        if len(chunk) < 16:
            chunk += bytes(16 - len(chunk))
        blocks.append(int.from_bytes(chunk, "big"))
    return blocks


def aes_gcm_encrypt(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> tuple[bytes, bytes]:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("bad AES-GCM input")
    rounds = mgr._expand_aes256(key)
    hash_key = int.from_bytes(mgr._encrypt_block(bytes(16), rounds), "big")
    counter_block = int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")

    def next_counter() -> bytes:
        nonlocal counter_block
        counter_block = (counter_block & ~0xFFFFFFFF) | ((counter_block + 1) & 0xFFFFFFFF)
        return counter_block.to_bytes(16, "big")

    out = bytearray()
    for offset in range(0, len(plain), 16):
        stream = mgr._encrypt_block(next_counter(), rounds)
        chunk = plain[offset:offset + 16]
        out.extend(left ^ right for left, right in zip(chunk, stream))
    ciphertext = bytes(out)
    digest = _ghash(hash_key, aad, ciphertext)
    mask = mgr._encrypt_block(nonce + b"\x00\x00\x00\x01", rounds)
    tag = bytes(left ^ right for left, right in zip(digest.to_bytes(16, "big"), mask))
    return ciphertext, tag


def host_public(scalar: int) -> bytes:
    point = mgr._p256_mul(scalar, (mgr.P256_GX, mgr.P256_GY, 1))
    x_coord, y_coord = mgr._p256_affine(point)
    return b"\x04" + mgr._i32(x_coord) + mgr._i32(y_coord)


def shared_x(scalar: int, peer: bytes) -> bytes:
    if len(peer) != 65 or peer[0] != 0x04:
        raise ValueError("The board returned a bad public key.")
    x_coord = int.from_bytes(peer[1:33], "big")
    y_coord = int.from_bytes(peer[33:65], "big")
    if not mgr._p256_on_curve(x_coord, y_coord):
        raise ValueError("The board returned a bad public key.")
    point = mgr._p256_mul(scalar, (x_coord, y_coord, 1))
    shared, _unused = mgr._p256_affine(point)
    return mgr._i32(shared)


def parse_begin(body: bytes) -> tuple[bytes, bytes, int]:
    if len(body) != 76 or body[0] != 0x01:
        raise ValueError("The board returned a bad session start.")
    salt = body[1:9]
    public = body[9:74]
    slot_max = int.from_bytes(body[74:76], "big")
    if slot_max < 1:
        raise ValueError("The board reported no password slots.")
    return salt, public, slot_max


def first_free(occupied: set[int], slot_max: int) -> int:
    for slot in range(slot_max):
        if slot not in occupied:
            return slot
    raise ValueError("The board has no free password slot.")


def session_apdu(p1: int, data: bytes = b"", le: int | None = None) -> bytes:
    if le is None and len(data) <= 255:
        return bytes((0x81, 0x22, p1, 0x00, len(data))) + data
    if len(data) > 65535:
        raise ValueError("password command is too long")
    apdu = bytes((0x81, 0x22, p1, 0x00, 0x00)) + len(data).to_bytes(2, "big") + data
    if le is None:
        return apdu
    if le > 65535:
        raise ValueError("bad response length")
    return apdu + le.to_bytes(2, "big")


def write_apdu(slot: int, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    if not 0 <= slot <= 0xFFFF or len(nonce) != 12 or len(tag) != 16:
        raise ValueError("bad password write")
    data = slot.to_bytes(2, "big") + nonce + ciphertext + tag
    return session_apdu(0x10, data)


def transport_aad(slot: int) -> bytes:
    return bytes((0x81, 0x22, 0x10, 0x00)) + slot.to_bytes(2, "big")


def require_ok(body: bytes, status: int, action: str) -> bytes:
    if status != mgr.SW_OK:
        raise OSError(f"{action} failed with {mgr.status_detail(body, status)}")
    return body


def format_added(slot: int, name: str, displayname: str) -> str:
    return f"Added password slot {slot}\nname         {name}\ndisplayname  {displayname}\n"


def passwd_delete_apdu(slot: int) -> bytes:
    data = slot.to_bytes(2, "big")
    return bytes((0x81, 0x22, 0x31, 0x00, len(data))) + data


def rollback_password_slot(pcsc, card: int, slot: int) -> None:
    # Same-auth window from the write still covers delete when possible.
    body, status = mgr.transmit_all(pcsc, card, passwd_delete_apdu(slot))
    if status == 0x6985:
        mgr.ask_button(pcsc, card)
        body, status = mgr.transmit_all(pcsc, card, passwd_delete_apdu(slot))
    if status != mgr.SW_OK:
        raise OSError(
            f"Rollback could not delete password slot {slot} ({mgr.status_detail(body, status)}); "
            "remove it manually."
        )


def add_password(pcsc, session, password: str, name: str, displayname: str) -> str:
    _context, card, _reader = session
    slots = mgr.list_password_slots(pcsc, card)
    body = require_ok(*mgr.transmit_all(pcsc, card, session_apdu(0x01, b"", 76)), "Session start")
    ident = secrets.token_bytes(8)
    slot = -1
    try:
        salt, public, slot_max = parse_begin(body)
        slot = first_free({item.slot for item in slots}, slot_max)
        scalar = secrets.randbelow(mgr.P256_N - 1) + 1
        shared = shared_x(scalar, public)
        session_key = bytearray(hkdf_sha256(shared, salt, INFO))
        try:
            proof = require_ok(
                *mgr.transmit_all(pcsc, card, session_apdu(0x02, host_public(scalar), 8)),
                "Session key",
            )
            if proof != hashlib.sha256(session_key).digest()[:8]:
                raise ValueError("The board returned a bad session check.")
            plain = bytearray(slot_plain(ident, name, displayname, password))
            try:
                nonce = secrets.token_bytes(12)
                ciphertext, tag = aes_gcm_encrypt(bytes(session_key), nonce, transport_aad(slot), bytes(plain))
                mgr.ask_button(pcsc, card)
                body, status = mgr.transmit_all(pcsc, card, write_apdu(slot, nonce, ciphertext, tag))
                if status == 0x6985:
                    raise OSError("The button was not pressed.")
                require_ok(body, status, "Password write")
            finally:
                plain[:] = b"\x00" * len(plain)
        finally:
            session_key[:] = b"\x00" * len(session_key)
    finally:
        try:
            mgr.transmit_all(pcsc, card, session_apdu(0x03))
        except OSError:
            pass
    # Only tags with values: empty name/displayname omit USERNAME/ALIAS.
    aliases = [displayname] if displayname else []
    try:
        tlv = mgr.build_index_tlv(username=name if name else "", aliases=aliases)
        mgr.put_index_entry(pcsc, card, mgr.INDEX_TYPE_PASSWD, mgr.passwd_record_id(ident), tlv)
    except OSError as exc:
        try:
            rollback_password_slot(pcsc, card, slot)
        except OSError as roll_exc:
            raise OSError(
                f"index_store failed ({exc}); password rollback also failed ({roll_exc})."
            ) from roll_exc
        raise OSError(f"index_store failed; password slot rolled back. ({exc})") from exc
    return format_added(slot, name, displayname)


def run(password: str, name: str, displayname: str) -> int:
    check_fields(password, name, displayname)
    pcsc = mgr.Pcsc()
    session, saw_reader = mgr.find_passwd(pcsc)
    if session is None:
        if saw_reader:
            print("The password applet did not answer.")
        else:
            print("Insert the nkey board.")
        return 1
    try:
        sys.stdout.write(add_password(pcsc, session, password, name, displayname))
        sys.stdout.flush()
    finally:
        mgr.close_session(pcsc, session)
    return 0


def self_test() -> int:
    check_fields("secret", "github", "work")
    check_fields("a", "", "")
    for bad in ("", "x" * 255, "密"):
        try:
            check_fields(bad, "github", "work")
            raise AssertionError(f"accepted password {bad!r}")
        except ValueError:
            pass
    try:
        check_fields("secret", "bad\nname", "work")
        raise AssertionError("control character was accepted")
    except ValueError as exc:
        if "control" not in str(exc):
            raise

    ident = b"\x11" * 8
    plain = slot_plain(ident, "github", "work", "secret")
    if plain != bytes((0x01, 0x08)) + ident + bytes((0x02, 0x06)) + b"github" + bytes((0x03, 0x04)) + b"work" + bytes((0x04, 0x06)) + b"secret":
        raise AssertionError("password TLV")

    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = transport_aad(3)
    ciphertext, tag = aes_gcm_encrypt(key, nonce, aad, b"hello")
    if (ciphertext + tag).hex() != "2f67ba77aac9526be93b0e60da63d3fed9e0595013":
        raise AssertionError("AES-GCM")

    derived = hkdf_sha256(b"\x03" * 32, b"\x04" * 8, INFO)
    if derived.hex() != "b9a895586066b599363a3a936f1c3d712d059be658c3d6fcb533a8af61b3db4e":
        raise AssertionError("session key")

    salt = b"\x04" * 8
    begin = bytes((0x01,)) + salt + b"\x04" + b"\x11" * 32 + b"\x22" * 32 + (55).to_bytes(2, "big")
    parsed_salt, public, slot_max = parse_begin(begin)
    if parsed_salt != salt or public[0] != 0x04 or slot_max != 55:
        raise AssertionError("session start parse")
    if first_free({0, 1, 3}, 55) != 2:
        raise AssertionError("free slot")
    try:
        first_free(set(range(4)), 4)
        raise AssertionError("full board was accepted")
    except ValueError as exc:
        if "no free" not in str(exc):
            raise
    if session_apdu(0x01, b"", 76) != bytes((0x81, 0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C)):
        raise AssertionError("session start APDU")
    if write_apdu(3, nonce, ciphertext, tag)[0:4] != bytes((0x81, 0x22, 0x10, 0x00)):
        raise AssertionError("write APDU")
    text = format_added(3, "github", "work")
    if text != "Added password slot 3\nname         github\ndisplayname  work\n":
        raise AssertionError(f"added text {text!r}")
    print("self-test ok")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Store one password slot. Arguments are password, name, and displayname.")
    parser.add_argument("password", nargs="?", help="ASCII password, 1 to 254 bytes")
    parser.add_argument("name", nargs="?", help="UTF-8 name")
    parser.add_argument("displayname", nargs="?", help="UTF-8 display name")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.self_test:
        return self_test()
    if args.password is None or args.name is None or args.displayname is None:
        print("Pass password, name, and displayname.")
        print("Example: python scripts/mgr.add.passwd.py secret github work")
        return 2
    try:
        return run(args.password, args.name, args.displayname)
    except Exception as exc:
        print(f"Add failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
