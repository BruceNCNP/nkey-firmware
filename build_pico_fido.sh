#!/bin/bash

mkdir -p build_release
mkdir -p release
rm -rf -- release/*
cd build_release

PICO_SDK_PATH="${PICO_SDK_PATH:-../../pico-sdk}"
SECURE_BOOT_PKEY="${SECURE_BOOT_PKEY:-../../ec_private_key.pem}"
rm -rf -- ./*
PICO_SDK_PATH="${PICO_SDK_PATH}" cmake .. -DPICO_BOARD=pico2 -DENABLE_EDDSA=ON -DSECURE_BOOT_PKEY=${SECURE_BOOT_PKEY}
make -j`nproc`
uf2=(nkey-rp2350-*.uf2)
if [ ${#uf2[@]} -ne 1 ]; then
    echo "Expected one nkey-rp2350 UF2, found: ${uf2[*]}" >&2
    exit 1
fi
mv "${uf2[0]}" ../release/
