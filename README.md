# nkey-firmware

Open-source USB hardware security key and local credential store firmware designed for **RP2350** microcontrollers, featuring physical button confirmation for password entry and SSH authorization.

* **Project Website & Demo:** [https://brucencnp.com/nkey/](https://brucencnp.com/nkey/)
* **Project Status:** Early prototype / pre-release preview. Firmware and companion host applications are under active development and not yet generally released.

## Origin & Non-Standard Authorization Behavior

This repository is adapted/forked from [pico-fido](https://github.com/polhenarejos/pico-fido) by Pol Henarejos (based on upstream commit `99337e1204348921452a3ce6613e8e17617d4c7d`). The vendored `pico-keys-sdk/` snapshot (based on commit `d8fce97ca761eb763869c77cc4d3b6fd0be1caf5`) is included directly inside this repository rather than managed as a nested Git submodule.

### Physical Button Authorization (Deviates from FIDO Standards)

* **Button-only authorization:** All user presence and authorization checks in this firmware are replaced by physical button confirmation rather than standard FIDO PIN/biometric/protocol-mandated user verification flows.
* **Non-standard FIDO behavior:** Because authorization relies on physical button presses instead of strict FIDO/CTAP specification flows, behavior may deviate from standard FIDO authenticators and strict compliance expectations.
* **Custom workflows:** Designed to pair with the `nkey` host tooling and custom commands/APDU/storage layout implemented in this fork.

## Hardware

* **Target platform:** Raspberry Pi **RP2350** (`PICO_BOARD=pico2`, 2 MB flash, 520 KB RAM).
* **Reference / validation board:** Currently developed and verified on **Waveshare RP2350-Zero-CM**, with default button and RGB LED GPIO mappings following that hardware layout.
* **Other RP2350 / RP2040 / display variants:** Additional board configurations or display/touch variants (such as Waveshare RP2350 touch-LCD boards or RP2040 targets) depend on board/build configuration and are not all guaranteed identical to the default `pico2` build.

## License

Licensed under the **GNU Affero General Public License v3.0** (`AGPL-3.0`). See [LICENSE](LICENSE). Vendored code in `pico-keys-sdk/` remains subject to its own license terms and original copyright notices.

## Repository Layout

| Path | Role |
| --- | --- |
| `src/fido/` | FIDO / authenticator and credential store firmware sources |
| `pico-keys-sdk/` | Vendored USB, storage, crypto, and board support SDK |
| `cmake/` | CMake helpers for build patch and firmware naming |
| `scripts/` | USB PC/SC debug helpers (`mgr.*`, `conf.py`); see [scripts/README.md](scripts/README.md) |
| `tests/` | Firmware tests |
| `workflows/` | CI workflow snippets |
| `CMakeLists.txt` | Top-level CMake build configuration |
| `pico_sdk_import.cmake` | Pico SDK CMake integration helper |

## Build

Build on WSL2 (such as Ubuntu 24.04) or a Linux host directly inside this repository checkout. Keep `PICO_SDK_PATH` on the Linux filesystem (for example `$HOME/pico-sdk`) with RP2350 (`PICO_BOARD=pico2`) support and an Arm GNU toolchain v13 or newer.

On first configure, CMake/SDK pulls dependencies such as Mbed TLS and TinyCBOR into `pico-keys-sdk/third-party/` (ignored by Git).

```sh
export PICO_SDK_PATH="$HOME/pico-sdk"
cmake -G Ninja -S . -B build -DPICO_BOARD=pico2 -DENABLE_EDDSA=ON
ninja -C build
```

## USB Debug Scripts

`scripts/` contains Python helpers that talk to a running board over USB CCID (PC/SC). They need no third-party packages: Windows uses `winscard.dll`, Linux uses `libpcsclite.so.1`. More detail is in [scripts/README.md](scripts/README.md).

Plug in the board so the host sees the smart-card reader, then run the commands from this repository root.

### Credential management

| Script | Role |
| --- | --- |
| `scripts/mgr.list.py` | List index rows, or `ssh` / `passwd` / `fido` crypt stores |
| `scripts/mgr.add.ssh.py` | Add one resident OpenSSH ed25519-sk credential |
| `scripts/mgr.add.passwd.py` | Add one password slot |
| `scripts/mgr.del.py` | Delete one SSH credential or password slot by id |

```sh
python scripts/mgr.list.py
python scripts/mgr.list.py ssh
python scripts/mgr.list.py passwd
python scripts/mgr.add.ssh.py root@192.168.1.1 mybox
python scripts/mgr.add.passwd.py 'secret' github work
python scripts/mgr.del.py 1122334455667788
```

Add and delete wait for the physical button (blue LED). List commands do not.

### Board configuration (PHY)

`scripts/conf.py` reads and writes the rescue PHY record (`EF_PHY`): LED GPIO, brightness, color order, USB VID/PID, and related options. A write replaces the whole record, so `set` reads first, merges the requested tags, then writes. Press the button when prompted.

```sh
python scripts/conf.py show
python scripts/conf.py set --led-gpio 16 --brightness 128 --led-order grb
python scripts/conf.py set --vidpid 2E8A:10FE --reboot
python scripts/conf.py clear-vidpid --reboot
```

### Offline self-tests

These checks do not need a board:

```sh
python scripts/mgr.list.py --self-test
python scripts/mgr.add.ssh.py --self-test
python scripts/mgr.add.passwd.py --self-test
python scripts/mgr.del.py --self-test
python scripts/conf.py --self-test
```