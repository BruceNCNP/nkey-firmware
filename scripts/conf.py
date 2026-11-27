#!/usr/bin/env python3
"""Read or write the board PHY (runtime pin / USB) record over USB CCID.

    python scripts/conf.py show
    python scripts/conf.py set --led-gpio 16 --brightness 128 --led-order grb
    python scripts/conf.py set --vidpid 2E8A:10FE --reboot
    python scripts/conf.py clear-vidpid --reboot
    python scripts/conf.py --self-test

The rescue applet stores PHY as TLV in EF_PHY. A write replaces the whole
record, so this script always reads first, merges the requested tags, then
writes. Press the button when the LED blinks blue. SW 6985 means the wait
ended without a press.

Windows uses winscard.dll. Linux uses libpcsclite.so.1. No extra packages.
"""

from __future__ import annotations

import argparse
import ctypes
import sys
import time
from ctypes import POINTER, byref, c_void_p

RESCUE_AID = bytes((0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21))
SW_OK = 0x9000
SW_CONDITIONS = 0x6985
MIN_RECORD = bytes((0x06, 0x02, 0x00, 0x00))

TAG_VIDPID = 0x00
TAG_LED_GPIO = 0x04
TAG_BRIGHTNESS = 0x05
TAG_OPTS = 0x06
TAG_BUTTON_TIMEOUT = 0x08
TAG_USB_PRODUCT = 0x09
TAG_CURVES = 0x0A
TAG_USB_ITF = 0x0B
TAG_LED_ORDER = 0x0C
TAG_CALIBRATED = 0x0F
TAG_UVEMU = 0x10

TAG_NAMES = {
    TAG_VIDPID: "vidpid",
    TAG_LED_GPIO: "led-gpio",
    TAG_BRIGHTNESS: "brightness",
    TAG_OPTS: "opts",
    TAG_BUTTON_TIMEOUT: "button-timeout",
    TAG_USB_PRODUCT: "usb-product",
    TAG_CURVES: "curves",
    TAG_USB_ITF: "usb-itf",
    TAG_LED_ORDER: "led-order",
    TAG_CALIBRATED: "calibrated",
    TAG_UVEMU: "uvemu",
}

LED_ORDERS = {"rgb": 0x00, "grb": 0x01}
OPT_FLAGS = {
    "wcid": 0x0001,
    "dimm": 0x0002,
    "disable-power-reset": 0x0004,
    "led-steady": 0x0008,
}


def hex_bytes(data: bytes) -> str:
    if not data:
        return "(empty)"
    return " ".join(f"{byte:02X}" for byte in data)


def parse_phy(data: bytes) -> list[tuple[int, bytes]]:
    fields: list[tuple[int, bytes]] = []
    index = 0
    while index < len(data):
        if index + 2 > len(data):
            raise ValueError("PHY record ended inside a tag header")
        tag = data[index]
        length = data[index + 1]
        index += 2
        if index + length > len(data):
            raise ValueError("PHY record ended inside a tag value")
        fields.append((tag, data[index : index + length]))
        index += length
    return fields


def encode_phy(fields: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    for tag, value in fields:
        if len(value) > 255:
            raise ValueError("PHY tag value is longer than 255 bytes")
        out.append(tag)
        out.append(len(value))
        out.extend(value)
    return bytes(out)


def field_map(fields: list[tuple[int, bytes]]) -> dict[int, bytes]:
    return {tag: value for tag, value in fields}


def ensure_opts(fields: dict[int, bytes]) -> dict[int, bytes]:
    out = dict(fields)
    if TAG_OPTS not in out:
        out[TAG_OPTS] = bytes((0x00, 0x00))
    return out


def ordered_fields(fields: dict[int, bytes]) -> list[tuple[int, bytes]]:
    preferred = (
        TAG_VIDPID,
        TAG_LED_GPIO,
        TAG_BRIGHTNESS,
        TAG_OPTS,
        TAG_BUTTON_TIMEOUT,
        TAG_USB_PRODUCT,
        TAG_CURVES,
        TAG_USB_ITF,
        TAG_LED_ORDER,
        TAG_CALIBRATED,
        TAG_UVEMU,
    )
    ordered: list[tuple[int, bytes]] = []
    for tag in preferred:
        if tag in fields:
            ordered.append((tag, fields[tag]))
    for tag, value in fields.items():
        if tag not in preferred:
            ordered.append((tag, value))
    return ordered or [(TAG_OPTS, bytes((0x00, 0x00)))]


def vidpid_text(value: bytes) -> str:
    if len(value) != 4:
        return hex_bytes(value)
    vid = (value[0] << 8) | value[1]
    pid = (value[2] << 8) | value[3]
    return f"{vid:04X}:{pid:04X}"


def parse_vidpid(text: str) -> bytes:
    raw = text.strip().replace(" ", "")
    if ":" in raw:
        left, right = raw.split(":", 1)
    elif "-" in raw:
        left, right = raw.split("-", 1)
    else:
        raise ValueError("VID/PID must look like 2E8A:10FE")
    vid = int(left, 16)
    pid = int(right, 16)
    if not (0 <= vid <= 0xFFFF and 0 <= pid <= 0xFFFF):
        raise ValueError("VID/PID out of range")
    return bytes((vid >> 8, vid & 0xFF, pid >> 8, pid & 0xFF))


def parse_u8(text: str, label: str) -> bytes:
    value = int(text, 0)
    if not 0 <= value <= 255:
        raise ValueError(f"{label} must be 0..255")
    return bytes((value,))


def parse_u16(text: str, label: str) -> bytes:
    value = int(text, 0)
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"{label} must be 0..65535")
    return bytes((value >> 8, value & 0xFF))


def parse_u32(text: str, label: str) -> bytes:
    value = int(text, 0)
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{label} must be 0..4294967295")
    return value.to_bytes(4, "big")


def parse_opts(text: str) -> bytes:
    raw = text.strip().lower()
    if raw.startswith("0x") or raw.isdigit():
        return parse_u16(raw, "opts")
    bits = 0
    for part in raw.replace(",", " ").split():
        if part not in OPT_FLAGS:
            known = ", ".join(sorted(OPT_FLAGS))
            raise ValueError(f"unknown opts flag {part!r}; use hex or: {known}")
        bits |= OPT_FLAGS[part]
    return bytes((bits >> 8, bits & 0xFF))


def parse_led_order(text: str) -> bytes:
    key = text.strip().lower()
    if key in LED_ORDERS:
        return bytes((LED_ORDERS[key],))
    value = int(text, 0)
    if value not in (0, 1):
        raise ValueError("led-order must be rgb, grb, 0, or 1")
    return bytes((value,))


def format_field(tag: int, value: bytes) -> str:
    name = TAG_NAMES.get(tag, f"tag-{tag:02X}")
    if tag == TAG_VIDPID:
        detail = vidpid_text(value)
    elif tag == TAG_LED_ORDER and len(value) == 1:
        detail = "rgb" if value[0] == 0 else "grb" if value[0] == 1 else hex_bytes(value)
    elif tag == TAG_OPTS and len(value) == 2:
        bits = (value[0] << 8) | value[1]
        flags = [name for name, mask in OPT_FLAGS.items() if bits & mask]
        detail = f"0x{bits:04X}" + (f" ({', '.join(flags)})" if flags else "")
    elif tag == TAG_USB_PRODUCT:
        text = value.split(b"\x00", 1)[0].decode("utf-8", "replace")
        detail = repr(text)
    elif tag in (TAG_LED_GPIO, TAG_BRIGHTNESS, TAG_BUTTON_TIMEOUT, TAG_USB_ITF, TAG_CALIBRATED, TAG_UVEMU) and len(value) == 1:
        detail = str(value[0])
    elif tag == TAG_CURVES and len(value) == 4:
        detail = f"0x{int.from_bytes(value, 'big'):08X}"
    else:
        detail = hex_bytes(value)
    return f"{name:16} {detail}"


def without_vidpid(body: bytes) -> tuple[bytes | None, str | None]:
    fields = field_map(parse_phy(body))
    if TAG_VIDPID not in fields:
        return None, None
    identity = vidpid_text(fields[TAG_VIDPID])
    del fields[TAG_VIDPID]
    rewritten = encode_phy(ordered_fields(ensure_opts(fields)))
    return rewritten, identity


def store_apdu(payload: bytes) -> bytes:
    if not 2 <= len(payload) <= 255:
        raise ValueError("PHY record does not fit in one write")
    return bytes((0x80, 0x1C, 0x01, 0x00, len(payload))) + payload


def read_apdu() -> bytes:
    return bytes((0x80, 0x1E, 0x01, 0x00, 0x00))


def reboot_apdu() -> bytes:
    return bytes((0x80, 0x1F, 0x00, 0x00))


def merge_set(body: bytes, updates: dict[int, bytes], drops: set[int]) -> bytes:
    fields = ensure_opts(field_map(parse_phy(body)))
    for tag in drops:
        fields.pop(tag, None)
    fields.update(updates)
    return encode_phy(ordered_fields(ensure_opts(fields)))


class Pcsc:
    """Thin PC/SC binding. Handles are pointer-sized on Windows and long on Linux."""

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
        if code != 0:
            raise OSError(f"SCardListReaders size failed: 0x{code & 0xFFFFFFFF:08X}")
        if self._unicode:
            buffer = ctypes.create_unicode_buffer(count.value)
        else:
            buffer = ctypes.create_string_buffer(count.value)
        code = self._list(self._context(context), None, ctypes.cast(buffer, c_void_p), byref(count))
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
        code = self._connect(self._context(context), name, 2, 3, byref(card), byref(protocol))
        if code != 0:
            return None
        return card.value

    def disconnect(self, card: int) -> None:
        self._lib.SCardDisconnect(self._context(card), 0)

    def transmit(self, card: int, apdu: bytes) -> tuple[bytes, int]:
        send = (ctypes.c_ubyte * len(apdu))(*apdu)
        recv = (ctypes.c_ubyte * 1024)()
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


def connect_rescue(pcsc: Pcsc) -> tuple[int, int, str] | None:
    context = pcsc.establish()
    for reader in pcsc.readers(context):
        card = pcsc.connect(context, reader)
        if card is None:
            continue
        select = bytes((0x00, 0xA4, 0x04, 0x00, len(RESCUE_AID))) + RESCUE_AID + bytes((0x00,))
        try:
            _body, status = pcsc.transmit(card, select)
        except OSError:
            pcsc.disconnect(card)
            continue
        if status == SW_OK:
            return context, card, reader
        pcsc.disconnect(card)
    pcsc.release(context)
    return None


def print_phy(body: bytes) -> None:
    print(f"PHY raw  {hex_bytes(body)}")
    fields = parse_phy(body)
    if not fields:
        print("PHY decoded  (empty)")
        return
    print("PHY decoded")
    for tag, value in fields:
        print(f"  {format_field(tag, value)}")


def write_phy(pcsc: Pcsc, card: int, payload: bytes, reboot: bool) -> int:
    print(f"Write {hex_bytes(payload)}")
    print("Press the button. The LED blinks blue while the board waits.")
    sys.stdout.flush()
    started = time.monotonic()
    _stored, store_status = pcsc.transmit(card, store_apdu(payload))
    elapsed = time.monotonic() - started
    if store_status == SW_CONDITIONS:
        print(f"Store failed. SW 6985 after {elapsed:.1f}s. The button was not pressed before the wait ended.")
        return 1
    if store_status != SW_OK:
        print(f"Store failed. SW {store_status:04X} after {elapsed:.1f}s.")
        return 1
    print(f"Store succeeded. SW 9000 after {elapsed:.1f}s.")
    if not reboot:
        return 0
    try:
        reboot_body, reboot_status = pcsc.transmit(card, reboot_apdu())
    except OSError as exc:
        print(f"Reboot requested. The card disconnected ({exc}).")
        return 0
    if reboot_status != SW_OK:
        print(f"Reboot failed. SW {reboot_status:04X}. Body {hex_bytes(reboot_body)}")
        return 1
    print("Reboot requested.")
    return 0


def collect_updates(args: argparse.Namespace) -> tuple[dict[int, bytes], set[int]]:
    updates: dict[int, bytes] = {}
    drops: set[int] = set()
    if args.led_gpio is not None:
        updates[TAG_LED_GPIO] = parse_u8(str(args.led_gpio), "led-gpio")
    if args.brightness is not None:
        updates[TAG_BRIGHTNESS] = parse_u8(str(args.brightness), "brightness")
    if args.button_timeout is not None:
        updates[TAG_BUTTON_TIMEOUT] = parse_u8(str(args.button_timeout), "button-timeout")
    if args.led_order is not None:
        updates[TAG_LED_ORDER] = parse_led_order(args.led_order)
    if args.vidpid is not None:
        updates[TAG_VIDPID] = parse_vidpid(args.vidpid)
    if args.usb_product is not None:
        raw = args.usb_product.encode("utf-8") + b"\x00"
        if len(raw) > 32:
            raise ValueError("usb-product is longer than 31 bytes plus NUL")
        updates[TAG_USB_PRODUCT] = raw
    if args.opts is not None:
        updates[TAG_OPTS] = parse_opts(args.opts)
    if args.curves is not None:
        updates[TAG_CURVES] = parse_u32(args.curves, "curves")
    if args.usb_itf is not None:
        updates[TAG_USB_ITF] = parse_u8(args.usb_itf, "usb-itf")
    if args.uvemu is not None:
        updates[TAG_UVEMU] = parse_u8(str(args.uvemu), "uvemu")
    if args.clear_vidpid_tag:
        drops.add(TAG_VIDPID)
    return updates, drops


def self_test() -> None:
    sample = bytes((0x00, 0x04, 0x2E, 0x8A, 0x10, 0xFE, 0x04, 0x01, 0x19, 0x06, 0x02, 0x00, 0x00, 0x0C, 0x01, 0x01))
    rewritten, identity = without_vidpid(sample)
    if identity != "2E8A:10FE":
        raise AssertionError(f"self-test read {identity}")
    if rewritten != bytes((0x04, 0x01, 0x19, 0x06, 0x02, 0x00, 0x00, 0x0C, 0x01, 0x01)):
        raise AssertionError(f"self-test rewrote other tags: {hex_bytes(rewritten or b'')}")
    merged = merge_set(sample, {TAG_BRIGHTNESS: bytes((0x40,))}, set())
    fields = field_map(parse_phy(merged))
    if fields[TAG_BRIGHTNESS] != bytes((0x40,)) or TAG_VIDPID not in fields:
        raise AssertionError("self-test merge lost tags")
    cleared = merge_set(sample, {}, {TAG_VIDPID})
    if TAG_VIDPID in field_map(parse_phy(cleared)):
        raise AssertionError("self-test clear-vidpid left the tag")
    if parse_vidpid("2E8A:10FE") != bytes((0x2E, 0x8A, 0x10, 0xFE)):
        raise AssertionError("self-test vidpid parse")
    if parse_led_order("grb") != bytes((0x01,)):
        raise AssertionError("self-test led-order")
    if store_apdu(MIN_RECORD)[:4] != bytes((0x80, 0x1C, 0x01, 0x00)):
        raise AssertionError("self-test store command")
    print("Self-test passed.")


def cmd_show() -> int:
    pcsc = Pcsc()
    session = connect_rescue(pcsc)
    if session is None:
        print("FAIL  no nkey rescue card. Insert the running board and run this again.")
        return 1
    context, card, reader = session
    try:
        print(f"Rescue card on {reader}")
        body, status = pcsc.transmit(card, read_apdu())
        if status != SW_OK:
            raise OSError(f"PHY read status 0x{status:04X}")
        print_phy(body)
        return 0
    finally:
        pcsc.disconnect(card)
        pcsc.release(context)


def cmd_set(args: argparse.Namespace) -> int:
    updates, drops = collect_updates(args)
    if not updates and not drops:
        print("Nothing to change. Pass at least one set/clear option.")
        return 2
    pcsc = Pcsc()
    session = connect_rescue(pcsc)
    if session is None:
        print("FAIL  no nkey rescue card. Insert the running board and run this again.")
        return 1
    context, card, reader = session
    try:
        print(f"Rescue card on {reader}")
        body, status = pcsc.transmit(card, read_apdu())
        if status != SW_OK:
            raise OSError(f"PHY read status 0x{status:04X}")
        print_phy(body)
        payload = merge_set(body, updates, drops)
        return write_phy(pcsc, card, payload, args.reboot)
    finally:
        pcsc.disconnect(card)
        pcsc.release(context)


def cmd_clear_vidpid(reboot: bool) -> int:
    pcsc = Pcsc()
    session = connect_rescue(pcsc)
    if session is None:
        print("FAIL  no nkey rescue card. Insert the running board and run this again.")
        return 1
    context, card, reader = session
    try:
        print(f"Rescue card on {reader}")
        body, status = pcsc.transmit(card, read_apdu())
        if status != SW_OK:
            raise OSError(f"PHY read status 0x{status:04X}")
        print_phy(body)
        rewritten, identity = without_vidpid(body)
        if rewritten is None:
            print("VID/PID tag 0x00 is absent. Nothing was written.")
            return 0
        print(f"Stored USB identity {identity}.")
        return write_phy(pcsc, card, rewritten, reboot)
    finally:
        pcsc.disconnect(card)
        pcsc.release(context)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read or write the nkey PHY record over USB CCID.")
    parser.add_argument("--self-test", action="store_true", help="check local PHY helpers and exit")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("show", help="read and decode the PHY record")

    set_p = sub.add_parser("set", help="merge tags into the PHY record and write")
    set_p.add_argument("--led-gpio", type=int, help="LED GPIO number")
    set_p.add_argument("--brightness", type=int, help="LED brightness 0..255")
    set_p.add_argument("--button-timeout", type=int, help="button wait seconds")
    set_p.add_argument("--led-order", help="rgb or grb")
    set_p.add_argument("--vidpid", help="USB identity, for example 2E8A:10FE")
    set_p.add_argument("--usb-product", help="USB product string")
    set_p.add_argument("--opts", help="hex value or flags: wcid,dimm,disable-power-reset,led-steady")
    set_p.add_argument("--curves", help="enabled curves bitmask (hex or decimal)")
    set_p.add_argument("--usb-itf", help="enabled USB interfaces bitmask")
    set_p.add_argument("--uvemu", type=int, help="UV emulation mode 0..255")
    set_p.add_argument("--clear-vidpid", dest="clear_vidpid_tag", action="store_true", help="drop tag 0x00")
    set_p.add_argument("--reboot", action="store_true", help="reboot after a successful write")

    clear_p = sub.add_parser("clear-vidpid", help="drop the stored USB VID/PID tag")
    clear_p.add_argument("--reboot", action="store_true", help="reboot after a successful write")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.self_test:
        self_test()
        return 0
    if args.command == "show":
        return cmd_show()
    if args.command == "set":
        return cmd_set(args)
    if args.command == "clear-vidpid":
        return cmd_clear_vidpid(args.reboot)
    parser.print_help()
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"FAIL  {exc}")
        raise SystemExit(1) from exc
