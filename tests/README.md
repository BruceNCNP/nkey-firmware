# Tests

Host tests build this firmware with `ENABLE_EMULATION=1` and talk to that process. They do not flash the RP2350 board.

## Docker

From the repository root, on a machine with Docker:

```sh
tests/build-in-docker.sh
tests/run-test-in-docker.sh
```

`tests/build-in-docker.sh` configures with `ENABLE_EMULATION=1` and `ENABLE_EDDSA=1`, then builds `build_in_docker/pico_fido`. The Windows `.bat` files next to the shell scripts call the same flow through Docker Desktop and mount this checkout at `/workspace`.

## Local emulation build

```sh
cmake -S . -B build_in_docker -DENABLE_EMULATION=1 -DENABLE_EDDSA=1
cmake --build build_in_docker
```

Run `./build_in_docker/pico_fido` and then `pytest tests`. The container entry script `tests/start-up-and-test.sh` does that after starting `pcscd`.

To run one test module:

```sh
pytest tests/pico-fido/test_000_getinfo.py
```
