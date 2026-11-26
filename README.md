# nkey-firmware

Firmware for **nkey**, a custom hardware authenticator and password/key store built on **Waveshare RP2350-Zero-CM** (RP2350, 2 MB flash, 520 KB RAM).

## Origin & Non-Standard Authorization Behavior

This repository is adapted/forked from [pico-fido](https://github.com/polhenarejos/pico-fido) by Pol Henarejos (based on upstream commit `99337e1204348921452a3ce6613e8e17617d4c7d`). The vendored `pico-keys-sdk/` snapshot (based on commit `d8fce97ca761eb763869c77cc4d3b6fd0be1caf5`) is included directly inside this repository rather than managed as a nested Git submodule.

### Physical Button Authorization (Deviates from FIDO Standards)

* **Button-only authorization:** All user presence and authorization checks in this firmware are replaced by physical button confirmation rather than standard FIDO PIN/biometric/protocol-mandated user verification flows.
* **Non-standard FIDO behavior:** Because authorization relies on physical button presses instead of strict FIDO/CTAP specification flows, behavior may deviate from standard FIDO authenticators and strict compliance expectations.
* **Custom workflows:** Pair with the `nkey` host tooling and custom commands/APDU/storage layout as implemented in this fork.

## Hardware

* **Primary target hardware:** Waveshare **RP2350-Zero-CM** (`PICO_BOARD=pico2`, RP2350 microcontroller, 2 MB flash, 520 KB RAM).
* **Board wiring:** Button and LED pin/wiring behavior follows the RP2350-Zero-CM setup used in this firmware.
* **Other RP2350 / RP2040 / display variants:** Additional board configurations or display/touch variants (such as Waveshare RP2350 touch-LCD boards or RP2040 targets) depend on board/build configuration and are not all guaranteed identical to the default `pico2` build.

## License

Licensed under the **GNU Affero General Public License v3.0** (`AGPL-3.0`). See [LICENSE](LICENSE). Vendored code in `pico-keys-sdk/` remains subject to its own license terms and original copyright notices.

## Repository Layout

| Path | Role |
| --- | --- |
| `src/fido/` | FIDO / authenticator firmware application sources |
| `pico-keys-sdk/` | Vendored USB, storage, crypto, and board support SDK |
| `cmake/` | CMake helpers for build patch and firmware naming |
| `tests/` | Firmware tests |
| `workflows/` | CI workflow snippets |
| `build_pico_fido.sh` | Release build helper script |
| `pico-fido-patch-vidpid.sh` | USB VID/PID patch helper script |
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
