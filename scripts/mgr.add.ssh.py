#!/usr/bin/env python3
"""Add one ed25519 resident SSH credential on the nkey board.

    python scripts/mgr.add.ssh.py root@192.168.1.1
    python scripts/mgr.add.ssh.py root@192.168.1.1 mybox box1
    python scripts/mgr.add.ssh.py --self-test

user@ip is required. The credential keeps rp.id ssh:, user.name as the
username only, and an optional short displayName from the first alias.
Full username, ip, and every alias are written to index_store after the
credential is created. Every run uses a new 32-byte user id. Press the
button when the LED blinks blue. The last line is the OpenSSH public key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import secrets
import sys
from pathlib import Path

RP_ID = "ssh:"
ALG_EDDSA = -8
CURVE_ED25519 = 6
TEXT_MAX = 64
USER_ID_LEN = 32
CTAP_MAKE_CREDENTIAL = 0x01
KEY_TYPE = "sk-ssh-ed25519@openssh.com"
RP_HASH_SSH = "e30610e8a162115960fe1ec223e6529c9f4b6e80200dcb5e5c321c8af1e2b1bf"


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


def split_target(user_at_ip: str) -> tuple[str, str]:
    if not user_at_ip or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in user_at_ip):
        raise ValueError("Pass user@ip as one token, for example root@192.168.1.1.")
    user, sep, host = user_at_ip.partition("@")
    if sep != "@" or not user or not host or "@" in host:
        raise ValueError("Pass user@ip as one token, for example root@192.168.1.1.")
    if len(user.encode("utf-8")) > TEXT_MAX:
        raise ValueError("username is longer than 64 bytes.")
    if len(host.encode("utf-8")) > TEXT_MAX:
        raise ValueError("host is longer than 64 bytes.")
    return user, host


def check_target(user_at_ip: str, aliases: list[str]) -> None:
    split_target(user_at_ip)
    seen: set[str] = set()
    for alias in aliases:
        if (
            not alias
            or alias.startswith("-")
            or "@" in alias
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in alias)
        ):
            raise ValueError(f"Alias {alias!r} must be one token without @.")
        if len(alias.encode("utf-8")) > 64:
            raise ValueError(f"Alias {alias!r} is longer than 64 bytes.")
        if alias in seen:
            raise ValueError(f"Alias {alias!r} is repeated.")
        seen.add(alias)
    if aliases and len(aliases[0].encode("utf-8")) > TEXT_MAX:
        raise ValueError("First alias is longer than 64 bytes for displayName.")


def cbor_head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("negative CBOR length")
    prefix = major << 5
    if value < 24:
        return bytes((prefix + value,))
    if value < 256:
        return bytes((prefix + 24, value))
    if value < 65536:
        return bytes((prefix + 25, value >> 8, value & 0xFF))
    if value < 2**32:
        return bytes((prefix + 26,)) + value.to_bytes(4, "big")
    raise ValueError("CBOR value is too large")


def cbor_uint(value: int) -> bytes:
    return cbor_head(0, value)


def cbor_int(value: int) -> bytes:
    if value >= 0:
        return cbor_uint(value)
    return cbor_head(1, -1 - value)


def cbor_bytes(data: bytes) -> bytes:
    return cbor_head(2, len(data)) + data


def cbor_text(text: str) -> bytes:
    raw = text.encode("utf-8")
    return cbor_head(3, len(raw)) + raw


def cbor_map(pairs: list[tuple[bytes, bytes]]) -> bytes:
    body = b"".join(key + value for key, value in pairs)
    return cbor_head(5, len(pairs)) + body


def cbor_array(items: list[bytes]) -> bytes:
    return cbor_head(4, len(items)) + b"".join(items)


def user_entity(user_id: bytes, username: str, aliases: list[str]) -> bytes:
    pairs = [
        (cbor_text("id"), cbor_bytes(user_id)),
        (cbor_text("name"), cbor_text(username)),
    ]
    if aliases:
        pairs.append((cbor_text("displayName"), cbor_text(aliases[0])))
    return cbor_map(pairs)


def credential_cbor(user_id: bytes, username: str, aliases: list[str], client_hash: bytes) -> bytes:
    if len(user_id) == 0 or len(user_id) > USER_ID_LEN or len(client_hash) != 32:
        raise ValueError("bad credential request")
    rp = cbor_map([
        (cbor_text("id"), cbor_text(RP_ID)),
        (cbor_text("name"), cbor_text(RP_ID)),
    ])
    param = cbor_map([
        (cbor_text("alg"), cbor_int(ALG_EDDSA)),
        (cbor_text("type"), cbor_text("public-key")),
    ])
    options = cbor_map([
        (cbor_text("rk"), bytes((0xF5,))),
    ])
    return cbor_map([
        (cbor_uint(1), cbor_bytes(client_hash)),
        (cbor_uint(2), rp),
        (cbor_uint(3), user_entity(user_id, username, aliases)),
        (cbor_uint(4), cbor_array([param])),
        (cbor_uint(7), options),
    ])


def ssh_string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def openssh_public_line(public_key: bytes, comment: str) -> str:
    if len(public_key) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    blob = ssh_string(KEY_TYPE.encode("ascii")) + ssh_string(public_key) + ssh_string(RP_ID.encode("ascii"))
    return KEY_TYPE + " " + base64.b64encode(blob).decode("ascii") + " " + comment


def rp_hash() -> bytes:
    return hashlib.sha256(RP_ID.encode("ascii")).digest()


def cred_id_of(auth_data: bytes) -> bytes:
    if len(auth_data) < 55 or (auth_data[32] & 0x40) == 0:
        raise ValueError("The board returned a short attestation.")
    cred_len = int.from_bytes(auth_data[53:55], "big")
    if cred_len < 1 or 55 + cred_len > len(auth_data):
        raise ValueError("The board returned a short attestation.")
    return auth_data[55:55 + cred_len]


def ed25519_public(auth_data: bytes) -> bytes:
    if len(auth_data) < 55 or (auth_data[32] & 0x40) == 0:
        raise ValueError("The board returned a short attestation.")
    if auth_data[:32] != rp_hash():
        raise ValueError("The board stored the key for a different application.")
    cred_len = int.from_bytes(auth_data[53:55], "big")
    start = 55 + cred_len
    if cred_len < 1 or start > len(auth_data):
        raise ValueError("The board returned a short attestation.")
    cose, end = mgr.cbor_decode(auth_data, start)
    if not isinstance(cose, dict):
        raise ValueError("The board returned a bad public key.")
    if (auth_data[32] & 0x80) == 0 and end != len(auth_data):
        raise ValueError("The board returned trailing attestation data.")
    public_key = cose.get(-2)
    if cose.get(1) != 1 or cose.get(3) != ALG_EDDSA or cose.get(-1) != CURVE_ED25519:
        raise ValueError("The board did not return an ed25519 public key.")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("The board did not return an ed25519 public key.")
    return public_key


def format_added(username: str, host: str, aliases: list[str], public_line: str) -> str:
    lines = [
        "Added ed25519 resident key",
        f"user.name  {username}",
        f"host       {host}",
    ]
    if aliases:
        lines.append("alias      " + " ".join(aliases))
    lines.append(public_line)
    return "\n".join(lines) + "\n"


def auth_data_of(body: bytes) -> bytes:
    value = mgr.cbor_one(body)
    auth_data = value.get(2)
    if not isinstance(auth_data, bytes):
        raise ValueError("The board returned a bad attestation.")
    return auth_data


def _cbor_bytes_field(data: bytes) -> bytes:
    size = len(data)
    if size < 24:
        return bytes((0x40 + size,)) + data
    if size < 256:
        return bytes((0x58, size)) + data
    if size < 65536:
        return bytes((0x59, size >> 8, size & 0xFF)) + data
    raise ValueError("credential id is too long")


def _cbor_text_field(text: str) -> bytes:
    raw = text.encode("utf-8")
    size = len(raw)
    if size < 24:
        return bytes((0x60 + size,)) + raw
    if size < 256:
        return bytes((0x78, size)) + raw
    raise ValueError("text is too long")


def _delete_cred_body(cred_id: bytes, token: bytes) -> bytes:
    params = (
        bytes((0xA1, 0x02, 0xA2))
        + _cbor_text_field("id")
        + _cbor_bytes_field(cred_id)
        + _cbor_text_field("type")
        + _cbor_text_field("public-key")
    )
    auth = mgr.hmac16(token, b"\x06" + params)
    return bytes((0xA4, 0x01, 0x06, 0x02)) + params + bytes((0x03, 0x01, 0x04, 0x50)) + auth


def rollback_ssh_credential(pcsc, session, cred_id: bytes) -> None:
    def action(token: bytes) -> None:
        deleted = mgr.ctap(pcsc, session[1], mgr._with_cmd(mgr.CTAP_CRED_MGMT, _delete_cred_body(cred_id, token)))
        if deleted is None:
            raise OSError("Rollback could not delete the credential; remove it manually.")

    if not mgr._select_fido(pcsc, session[1]):
        raise OSError("Rollback could not select FIDO; remove the credential manually.")
    mgr.call_with_token(pcsc, session, action)


def add_resident(pcsc, session, user_at_ip: str, aliases: list[str]) -> str:
    _context, card, _reader = session
    username, host = split_target(user_at_ip)
    # Same constraints as FIDO user.name: reject before any board write.
    if not username or len(username.encode("utf-8")) > TEXT_MAX:
        raise ValueError("username cannot be stored in FIDO user.name (empty or longer than 64 bytes).")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in username):
        raise ValueError("username cannot be stored in FIDO user.name (control character).")
    user_id = secrets.token_bytes(USER_ID_LEN)
    payload = credential_cbor(
        user_id,
        username,
        aliases,
        secrets.token_bytes(32),
    )
    mgr.ask_button(pcsc, card, reselect_fido=True)
    body = mgr.ctap(pcsc, card, mgr._with_cmd(CTAP_MAKE_CREDENTIAL, payload))
    if body is None:
        raise ValueError("The board did not create a credential.")
    auth_data = auth_data_of(body)
    cred_id = cred_id_of(auth_data)
    try:
        tlv = mgr.build_index_tlv(username=username, ip=host, aliases=aliases)
        mgr.put_index_entry(pcsc, card, mgr.INDEX_TYPE_SSH, user_id, tlv)
    except OSError as exc:
        try:
            rollback_ssh_credential(pcsc, session, cred_id)
        except OSError as roll_exc:
            raise OSError(
                f"index_store failed ({exc}); credential rollback also failed ({roll_exc}). "
                "Remove the leftover credential manually."
            ) from roll_exc
        raise OSError(f"index_store failed; credential rolled back. ({exc})") from exc
    public_line = openssh_public_line(ed25519_public(auth_data), user_at_ip)
    return format_added(username, host, aliases, public_line)


def run(user_at_ip: str, aliases: list[str]) -> int:
    check_target(user_at_ip, aliases)
    pcsc = mgr.Pcsc()
    session, saw_reader = mgr.find_fido(pcsc)
    if session is None:
        if saw_reader:
            print("The FIDO applet did not answer.")
        else:
            print("Insert the nkey board.")
        return 1
    try:
        sys.stdout.write(add_resident(pcsc, session, user_at_ip, aliases))
        sys.stdout.flush()
    finally:
        mgr.close_session(pcsc, session)
    return 0


def _cose_ed25519(public_key: bytes) -> bytes:
    return cbor_map([
        (cbor_uint(1), cbor_uint(1)),
        (cbor_uint(3), cbor_int(ALG_EDDSA)),
        (cbor_int(-1), cbor_uint(CURVE_ED25519)),
        (cbor_int(-2), cbor_bytes(public_key)),
    ])


def _auth_data(public_key: bytes, rp: bytes | None = None) -> bytes:
    cred_id = b"\x11" * 42
    cose = _cose_ed25519(public_key)
    return (
        (rp if rp is not None else rp_hash())
        + bytes((0x41,))
        + b"\x00\x00\x00\x01"
        + b"\x00" * 16
        + len(cred_id).to_bytes(2, "big")
        + cred_id
        + cose
    )


def self_test() -> int:
    if rp_hash().hex() != RP_HASH_SSH:
        raise AssertionError("ssh: rp id hash")
    check_target("root@192.168.1.1", [])
    check_target("root@192.168.1.1", ["mybox", "box1"])
    for bad in ("", "root", "root@", "@192.168.1.1", "a@b@c", "root@host name", "u@" + ("a" * 65)):
        try:
            check_target(bad, [])
            raise AssertionError(f"accepted {bad!r}")
        except ValueError:
            pass
    try:
        check_target("root@10.0.0.1", ["mybox", "mybox"])
        raise AssertionError("repeated alias was accepted")
    except ValueError as exc:
        if "repeated" not in str(exc):
            raise
    try:
        check_target("root@10.0.0.1", ["my@box"])
        raise AssertionError("alias with @ was accepted")
    except ValueError as exc:
        if "without @" not in str(exc):
            raise
    try:
        check_target("root@10.0.0.1", ["a" * 65])
        raise AssertionError("long aliases were accepted")
    except ValueError as exc:
        if "64 bytes" not in str(exc):
            raise

    user_id = b"\x01" * USER_ID_LEN
    client_hash = b"\x02" * 32
    decoded = mgr.cbor_one(credential_cbor(user_id, "root", ["mybox", "box1"], client_hash))
    user = decoded[3]
    if user["name"] != "root" or user["id"] != user_id or user["displayName"] != "mybox":
        raise AssertionError("user.name should be username only; displayName is first alias")
    if decoded[1] != client_hash or decoded[2]["id"] != RP_ID or decoded[2]["name"] != RP_ID:
        raise AssertionError("relying party")
    if decoded[4][0]["alg"] != ALG_EDDSA or decoded[4][0]["type"] != "public-key" or decoded[7]["rk"] is not True:
        raise AssertionError("ed25519 resident options")
    plain = mgr.cbor_one(credential_cbor(user_id, "root", [], client_hash))
    if "displayName" in plain[3] or plain[3]["name"] != "root":
        raise AssertionError("aliases are optional")

    public_key = bytes(range(32))
    if ed25519_public(_auth_data(public_key)) != public_key:
        raise AssertionError("public key parse")
    try:
        ed25519_public(_auth_data(public_key, b"\x00" * 32))
        raise AssertionError("wrong application was accepted")
    except ValueError as exc:
        if "application" not in str(exc):
            raise
    line = openssh_public_line(public_key, "root@10.0.0.1")
    kind, blob, comment = line.split(" ")
    raw = base64.b64decode(blob)
    expect = ssh_string(KEY_TYPE.encode("ascii")) + ssh_string(public_key) + ssh_string(RP_ID.encode("ascii"))
    if kind != KEY_TYPE or comment != "root@10.0.0.1" or raw != expect or raw[:4] != b"\x00\x00\x00\x1a":
        raise AssertionError("openssh public key")
    text = format_added("root", "10.0.0.1", ["mybox", "box1"], line)
    if "user.name  root" not in text or "host       10.0.0.1" not in text:
        raise AssertionError(f"added text {text!r}")
    if "alias      mybox box1" not in text or not text.endswith(line + "\n"):
        raise AssertionError(f"added text {text!r}")
    if "alias" in format_added("root", "10.0.0.1", [], line):
        raise AssertionError("empty alias line")
    sample = _auth_data(public_key)
    if cred_id_of(sample) != b"\x11" * 42:
        raise AssertionError("cred id parse")
    print("self-test ok")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Add one ed25519 resident SSH credential. user@ip sets username and host; aliases go to index_store."
    )
    parser.add_argument("user_at_ip", nargs="?", help="user@ip; username goes to user.name, host to index")
    parser.add_argument("alias", nargs="*", help="optional aliases stored in index_store")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.self_test:
        return self_test()
    if not args.user_at_ip:
        print("Pass user@ip. Aliases are optional.")
        print("Example: python scripts/mgr.add.ssh.py root@192.168.1.1")
        print("Example: python scripts/mgr.add.ssh.py root@192.168.1.1 mybox box1")
        return 2
    try:
        return run(args.user_at_ip, args.alias)
    except Exception as exc:
        print(f"Add failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
