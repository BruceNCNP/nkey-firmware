#!/usr/bin/env python3
"""Delete one SSH credential or password slot.

    python scripts/mgr.del.py alice
    python scripts/mgr.del.py 1122334455667788
    python scripts/mgr.del.py --self-test

One argument is required. It is the id column from mgr.list, for an ssh row
or a passwd row. A number is an id, not a row. Two entries with the same id
are left in place. Press the button when the LED blinks blue.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


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


def choose(rows: list, slots: list, target: str) -> tuple[str, int, object]:
    matches = []
    index = 1
    for row in rows:
        if row.rp_id == "ssh:" and mgr.format_user_id(row.user_id) == target:
            matches.append(("ssh", index, row))
        index += 1
    for slot in slots:
        if mgr.format_user_id(slot.ident) == target:
            matches.append(("passwd", index, slot))
        index += 1
    if not matches:
        raise ValueError(f"No ssh or password entry with id {target!r}.")
    if len(matches) > 1:
        raise ValueError(f"id {target!r} matches more than one entry.")
    return matches[0]


def cbor_bytes(data: bytes) -> bytes:
    size = len(data)
    if size < 24:
        return bytes((0x40 + size,)) + data
    if size < 256:
        return bytes((0x58, size)) + data
    if size < 65536:
        return bytes((0x59, size >> 8, size & 0xFF)) + data
    raise ValueError("credential id is too long")


def cbor_text(text: str) -> bytes:
    raw = text.encode("utf-8")
    size = len(raw)
    if size < 24:
        return bytes((0x60 + size,)) + raw
    if size < 256:
        return bytes((0x78, size)) + raw
    if size < 65536:
        return bytes((0x79, size >> 8, size & 0xFF)) + raw
    raise ValueError("text is too long")


def delete_params(cred_id: bytes) -> bytes:
    descriptor = (
        bytes((0xA2,))
        + cbor_text("id")
        + cbor_bytes(cred_id)
        + cbor_text("type")
        + cbor_text("public-key")
    )
    return bytes((0xA1, 0x02)) + descriptor


def delete_body(cred_id: bytes, token: bytes) -> bytes:
    params = delete_params(cred_id)
    auth = mgr.hmac16(token, b"\x06" + params)
    return bytes((0xA4, 0x01, 0x06, 0x02)) + params + bytes((0x03, 0x01, 0x04, 0x50)) + auth


def passwd_delete_apdu(slot: int) -> bytes:
    if slot < 0 or slot > 0xFFFF:
        raise ValueError("bad password slot")
    data = slot.to_bytes(2, "big")
    return bytes((0x81, 0x22, 0x31, 0x00, len(data))) + data


def deleted_line(kind: str, index: int, item) -> str:
    if kind == "ssh":
        record = mgr._record(index, item)
    else:
        record = mgr._password_record(index, item)
    widths = mgr._widths([record])
    return mgr._join(record, (max(len(str(index)), widths[0]), *widths[1:]))


def delete_ssh(pcsc, session, index: int, row) -> int:
    _context, card, _reader = session
    shown = mgr.format_user_id(row.user_id)
    if not row.cred_id:
        print(f"id {shown!r} has no credential id.")
        return 1
    if not mgr._select_fido(pcsc, card):
        print("The FIDO applet did not answer.")
        return 1

    def action(token: bytes) -> int:
        deleted = mgr.ctap(pcsc, card, mgr._with_cmd(mgr.CTAP_CRED_MGMT, delete_body(row.cred_id, token)))
        if deleted is None:
            print(f"id {shown!r} was not on the board.")
            return 1
        record_id = row.user_id
        if len(record_id) < mgr.INDEX_RECORD_ID_LEN:
            record_id = record_id + bytes(mgr.INDEX_RECORD_ID_LEN - len(record_id))
        elif len(record_id) > mgr.INDEX_RECORD_ID_LEN:
            record_id = record_id[:mgr.INDEX_RECORD_ID_LEN]
        try:
            mgr.delete_index_entry(pcsc, card, mgr.INDEX_TYPE_SSH, record_id)
        except OSError as exc:
            print(f"Deleted credential; index cleanup failed: {exc}")
            print("Deleted " + deleted_line("ssh", index, row))
            return 0
        print("Deleted " + deleted_line("ssh", index, row))
        return 0

    return mgr.call_with_token(pcsc, session, action)


def delete_passwd(pcsc, card: int, index: int, slot) -> int:
    mgr.ask_button(pcsc, card)
    body, status = mgr.transmit_all(pcsc, card, passwd_delete_apdu(slot.slot))
    if status == 0x6985:
        print("The button was not pressed.")
        return 1
    if status == 0x6984:
        print("That password slot is empty.")
        return 1
    if status != mgr.SW_OK:
        print(f"Password delete failed with {mgr.status_detail(body, status)}")
        return 1
    try:
        mgr.delete_index_entry(pcsc, card, mgr.INDEX_TYPE_PASSWD, mgr.passwd_record_id(slot.ident))
    except OSError as exc:
        print(f"Deleted password; index cleanup failed: {exc}")
    print("Deleted " + deleted_line("passwd", index, slot))
    return 0


def delete_target(pcsc, session, target: str) -> int:
    _context, card, _reader = session
    if mgr._select_fido(pcsc, card):
        rows = mgr.enumerate_credentials(pcsc, card)
    else:
        rows = []
    try:
        slots = mgr.list_password_slots(pcsc, card)
    except OSError:
        slots = []
    try:
        kind, index, item = choose(rows, slots, target)
    except ValueError as exc:
        sys.stdout.write(mgr.format_list(rows, slots))
        print(exc)
        return 1
    if kind == "ssh":
        return delete_ssh(pcsc, session, index, item)
    return delete_passwd(pcsc, card, index, item)


def run(target: str) -> int:
    pcsc = mgr.Pcsc()
    session, saw_reader = mgr.find_nkey(pcsc)
    if session is None:
        if saw_reader:
            print("The board did not answer.")
        else:
            print("Insert the nkey board.")
        return 1
    try:
        return delete_target(pcsc, session, target)
    finally:
        mgr.close_session(pcsc, session)


def self_test() -> int:
    alice = mgr.Resident("ssh:", b"alice" + b"\x00" * 27, "openssh", "openssh", b"\x11" * 42)
    null_row = mgr.Resident("ssh:", b"null", "openssh", "openssh", b"\x22" * 42)
    other = mgr.Resident("example.com", b"bank", "bank", "", b"\x33" * 42)
    password = mgr.PasswordSlot(3, "github", "work", bytes((0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)))
    rows = [alice, other, null_row]
    kind, index, chosen = choose(rows, [], "alice")
    if kind != "ssh" or index != 1 or chosen is not alice:
        raise AssertionError("id selects the ssh row")
    kind, index, chosen = choose(rows, [], "null")
    if kind != "ssh" or index != 3 or chosen is not null_row:
        raise AssertionError("id keeps the mixed list index")
    try:
        choose(rows, [], "2")
        raise AssertionError("row number was accepted")
    except ValueError as exc:
        if "id '2'" not in str(exc):
            raise
    try:
        choose(rows, [], "bank")
        raise AssertionError("non-ssh id was accepted")
    except ValueError as exc:
        if "id 'bank'" not in str(exc):
            raise
    duplicate = [alice, mgr.Resident("ssh:", b"alice\x00", "openssh", "openssh", b"\x44" * 42)]
    try:
        choose(duplicate, [], "alice")
        raise AssertionError("duplicate id was accepted")
    except ValueError as exc:
        if "more than one" not in str(exc):
            raise
    kind, index, chosen = choose(rows, [password], "1122334455667788")
    if kind != "passwd" or index != 4 or chosen is not password:
        raise AssertionError("password id was not selected")
    collide = mgr.PasswordSlot(1, "github", "work", b"alice")
    try:
        choose(rows, [collide], "alice")
        raise AssertionError("ssh and password with the same id were accepted")
    except ValueError as exc:
        if "more than one" not in str(exc):
            raise
    cred_id = b"\xab" * 42
    descriptor = cbor_text("id") + cbor_bytes(cred_id) + cbor_text("type") + cbor_text("public-key")
    body = bytes((0xA3, 0x06, 0xA1, 0x62, 0x69, 0x64, 0x45)) + b"alice" + bytes((0x07, 0xA2)) + descriptor + bytes((0x09, 0x01))
    parsed, total = mgr.parse_cred(body)
    if parsed.cred_id != cred_id or mgr.format_user_id(parsed.user_id) != "alice" or total != 1:
        raise AssertionError("credential id was not kept")
    token = b"\x11" * 32
    params = delete_params(cred_id)
    request = delete_body(cred_id, token)
    if not request.startswith(bytes((0xA4, 0x01, 0x06, 0x02)) + params):
        raise AssertionError("delete command layout")
    if not request.endswith(mgr.hmac16(token, b"\x06" + params)):
        raise AssertionError("delete auth")
    if passwd_delete_apdu(3) != bytes((0x81, 0x22, 0x31, 0x00, 0x02, 0x00, 0x03)):
        raise AssertionError("password delete APDU")
    line = deleted_line("passwd", 4, password)
    if "passwd" not in line or "1122334455667788" not in line or "github" not in line or "work" not in line:
        raise AssertionError(f"deleted password line {line!r}")
    print("self-test ok")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Delete one ssh or password entry by the id column from mgr.list.")
    parser.add_argument("target", nargs="?", help="id column from mgr.list")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.self_test:
        return self_test()
    if not args.target:
        print("Pass the id column from mgr.list.")
        print("Example: python scripts/mgr.del.py alice")
        print("Example: python scripts/mgr.del.py 1122334455667788")
        return 2
    try:
        return run(args.target)
    except Exception as exc:
        print(f"Delete failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
