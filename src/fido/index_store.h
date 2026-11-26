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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _INDEX_STORE_H_
#define _INDEX_STORE_H_

#include <stdint.h>
#include <stdbool.h>

/* Dynamic data-pool files. Slots 0xE600..0xE6FE (255). 0xE6FF unused. */
#define INDEX_FID_BASE 0xE600u
#define INDEX_FID_LAST 0xE6FEu
#define INDEX_SLOT_MAX 255u
#define INDEX_RECORD_ID_LEN 32u
#define INDEX_HEADER_LEN 38u
#define INDEX_RECORD_MAX 512u
#define INDEX_ALIAS_MAX 64u

#define INDEX_VERSION 0x01u

#define INDEX_TYPE_SSH 0x01u
#define INDEX_TYPE_PASSWD 0x02u
#define INDEX_TYPE_OTP 0x03u
#define INDEX_TYPE_OATH 0x04u
#define INDEX_TYPE_FIDO 0x05u

#define IX_TAG_USERNAME 0x01u
#define IX_TAG_IP 0x02u
#define IX_TAG_URL 0x03u
#define IX_TAG_ALIAS 0x04u

enum {
    INDEX_STORE_OK = 0,
    INDEX_STORE_NOT_FOUND = 1,
    INDEX_STORE_FULL = 2,
    INDEX_STORE_BAD = 3,
};

typedef struct {
    uint8_t version;
    uint8_t entry_type;
    uint8_t flags;
    uint8_t reserved;
    uint8_t record_id[INDEX_RECORD_ID_LEN];
    uint16_t tlv_len;
    uint16_t total;
    const uint8_t *tlv;
} index_rec_t;

int index_store_put(uint8_t entry_type, const uint8_t record_id[INDEX_RECORD_ID_LEN],
    const uint8_t *tlv, uint16_t tlv_len);
int index_store_delete(uint8_t entry_type, const uint8_t record_id[INDEX_RECORD_ID_LEN]);
int index_store_get(uint8_t entry_type, const uint8_t record_id[INDEX_RECORD_ID_LEN],
    uint8_t *out, uint16_t out_max, uint16_t *out_len);
bool index_store_parse(const uint8_t *p, uint32_t len, index_rec_t *rec);
bool index_store_tlv_ok(const uint8_t *tlv, uint16_t tlv_len);
bool index_store_next(uint16_t start_slot, uint16_t *slot_out, index_rec_t *rec,
    const uint8_t **raw, uint16_t *raw_len);

void index_sync_arm(void);
bool index_sync_allow_write(void);
void index_sync_consume(void);

#endif
