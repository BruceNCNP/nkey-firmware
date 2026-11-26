/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _PASSWD_STORE_H_
#define _PASSWD_STORE_H_

#include <stdint.h>
#include <stdbool.h>

/* Dynamic data-pool files. No FILE_PERSISTENT flag.
 * Slot fid = PASSWD_FID_BASE + slot, so 55 slots use 0xE400..0xE436.
 * PASSWD_KEY_FID holds the 32-byte storage key. A later SLOT_MAX increase
 * must keep the last slot fid at or below 0xE4FE. */
#define PASSWD_FID_BASE 0xE400u
#define PASSWD_KEY_FID 0xE4FFu
#define PASSWD_RECORD_MAX 548u
#define PASSWD_SLOT_MAX 55u

enum {
    PASSWD_STORE_OK = 0,
    PASSWD_STORE_NOT_FOUND = 1,
    PASSWD_STORE_FULL = 2,
    PASSWD_STORE_BAD = 3,
    PASSWD_STORE_CRYPTO = 4,
};

void passwd_store_init(void);
bool passwd_store_ready(void);
uint16_t passwd_store_slot_max(void);
int passwd_store_public_key(uint8_t q[65]);
int passwd_store_ecdh(const uint8_t q_host[65], uint8_t shared[32]);
bool passwd_store_exists(uint16_t slot);
int passwd_store_put(uint16_t slot, const uint8_t *plain, uint16_t plain_len);
int passwd_store_get(uint16_t slot, uint8_t *plain, uint16_t plain_max, uint16_t *plain_len);
int passwd_store_delete(uint16_t slot);

#endif
