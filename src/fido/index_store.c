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

#include "index_store.h"
#include "maintenance.h"
#include "picokeys.h"
#include "file.h"
#include "flash.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif

#include <string.h>

#define INDEX_COMMIT_TIMEOUT_MS 500u
#define INDEX_SYNC_MS 15000u

_Static_assert(INDEX_SLOT_MAX == 255u, "index slot count");
_Static_assert((uint16_t)(INDEX_FID_BASE + INDEX_SLOT_MAX - 1u) == INDEX_FID_LAST, "last fid");
_Static_assert(INDEX_HEADER_LEN == 38u, "fixed header");

static uint32_t sync_until;
static bool sync_armed;

static uint16_t slot_fid(uint16_t slot) {
    return (uint16_t)(INDEX_FID_BASE + slot);
}

void index_sync_arm(void) {
    sync_until = board_millis() + INDEX_SYNC_MS;
    sync_armed = true;
}

bool index_sync_allow_write(void) {
    if (maintenance_skip_button()) {
        return true;
    }
    if (!sync_armed) {
        return false;
    }
    if ((int32_t)(board_millis() - sync_until) >= 0) {
        sync_armed = false;
        return false;
    }
    /* Leave armed until a successful PUT/DEL consumes it (index_sync_consume). */
    return true;
}

void index_sync_consume(void) {
    sync_armed = false;
}

bool index_store_tlv_ok(const uint8_t *tlv, uint16_t tlv_len) {
    uint16_t pos = 0;
    bool seen_user = false;
    bool seen_ip = false;
    bool seen_url = false;

    if (tlv == NULL && tlv_len != 0) {
        return false;
    }
    while (pos < tlv_len) {
        uint8_t tag;
        uint16_t flen;
        if ((uint16_t)(pos + 3u) > tlv_len) {
            return false;
        }
        tag = tlv[pos];
        flen = get_uint16_be(tlv + pos + 1);
        pos = (uint16_t)(pos + 3u);
        if ((uint16_t)(pos + flen) > tlv_len) {
            return false;
        }
        if (tag == 0x00u) {
            return false;
        }
        if (tag == IX_TAG_USERNAME) {
            if (seen_user) {
                return false;
            }
            seen_user = true;
        }
        else if (tag == IX_TAG_IP) {
            if (seen_ip) {
                return false;
            }
            seen_ip = true;
        }
        else if (tag == IX_TAG_URL) {
            if (seen_url) {
                return false;
            }
            seen_url = true;
        }
        else if (tag == IX_TAG_ALIAS) {
            if (flen > INDEX_ALIAS_MAX) {
                return false;
            }
        }
        pos = (uint16_t)(pos + flen);
    }
    return pos == tlv_len;
}

bool index_store_parse(const uint8_t *p, uint32_t len, index_rec_t *rec) {
    uint16_t tlv_len;
    uint32_t total;

    if (p == NULL || rec == NULL || len < INDEX_HEADER_LEN) {
        return false;
    }
    if (p[0] != INDEX_VERSION || p[2] != 0x00u || p[3] != 0x00u) {
        return false;
    }
    tlv_len = get_uint16_be(p + 36);
    total = (uint32_t)INDEX_HEADER_LEN + tlv_len;
    if (total > len || total > INDEX_RECORD_MAX) {
        return false;
    }
    if (!index_store_tlv_ok(p + INDEX_HEADER_LEN, tlv_len)) {
        return false;
    }
    rec->version = p[0];
    rec->entry_type = p[1];
    rec->flags = p[2];
    rec->reserved = p[3];
    memcpy(rec->record_id, p + 4, INDEX_RECORD_ID_LEN);
    rec->tlv_len = tlv_len;
    rec->total = (uint16_t)total;
    rec->tlv = p + INDEX_HEADER_LEN;
    return true;
}

static const uint8_t *slot_raw(uint16_t slot, index_rec_t *rec, uint16_t *raw_len) {
    file_t *ef;
    const uint8_t *p;
    uint32_t size;

    if (slot >= INDEX_SLOT_MAX) {
        return NULL;
    }
    ef = file_search(slot_fid(slot));
    if (!file_has_data(ef)) {
        return NULL;
    }
    p = file_get_data(ef);
    size = file_get_size(ef);
    if (!index_store_parse(p, size, rec)) {
        return NULL;
    }
    if (raw_len != NULL) {
        *raw_len = rec->total;
    }
    return p;
}

static int find_key(uint8_t entry_type, const uint8_t record_id[INDEX_RECORD_ID_LEN],
    uint16_t *slot_out) {
    uint16_t slot;
    index_rec_t rec;

    for (slot = 0; slot < INDEX_SLOT_MAX; slot++) {
        if (slot_raw(slot, &rec, NULL) == NULL) {
            continue;
        }
        if (rec.entry_type == entry_type &&
            memcmp(rec.record_id, record_id, INDEX_RECORD_ID_LEN) == 0) {
            if (slot_out != NULL) {
                *slot_out = slot;
            }
            return INDEX_STORE_OK;
        }
    }
    return INDEX_STORE_NOT_FOUND;
}

static int find_free(uint16_t *slot_out) {
    uint16_t slot;
    index_rec_t rec;

    for (slot = 0; slot < INDEX_SLOT_MAX; slot++) {
        if (slot_raw(slot, &rec, NULL) == NULL) {
            file_t *ef = file_search(slot_fid(slot));
            if (ef != NULL && file_has_data(ef)) {
                continue;
            }
            if (slot_out != NULL) {
                *slot_out = slot;
            }
            return INDEX_STORE_OK;
        }
    }
    return INDEX_STORE_FULL;
}

int index_store_put(uint8_t entry_type, const uint8_t record_id[INDEX_RECORD_ID_LEN],
    const uint8_t *tlv, uint16_t tlv_len) {
    uint8_t buf[INDEX_RECORD_MAX];
    uint16_t slot;
    uint16_t total;
    file_t *ef;
    int wr;

    if (record_id == NULL || (tlv == NULL && tlv_len != 0)) {
        return INDEX_STORE_BAD;
    }
    if ((uint32_t)INDEX_HEADER_LEN + tlv_len > INDEX_RECORD_MAX) {
        return INDEX_STORE_BAD;
    }
    if (!index_store_tlv_ok(tlv, tlv_len)) {
        return INDEX_STORE_BAD;
    }
    if (find_key(entry_type, record_id, &slot) != INDEX_STORE_OK) {
        if (find_free(&slot) != INDEX_STORE_OK) {
            return INDEX_STORE_FULL;
        }
    }

    buf[0] = INDEX_VERSION;
    buf[1] = entry_type;
    buf[2] = 0x00;
    buf[3] = 0x00;
    memcpy(buf + 4, record_id, INDEX_RECORD_ID_LEN);
    put_uint16_be(tlv_len, buf + 36);
    if (tlv_len > 0) {
        memcpy(buf + INDEX_HEADER_LEN, tlv, tlv_len);
    }
    total = (uint16_t)(INDEX_HEADER_LEN + tlv_len);

    ef = file_new(slot_fid(slot));
    if (ef == NULL) {
        return INDEX_STORE_FULL;
    }
    wr = file_put_data(ef, CONST_BYTE_ARRAY(buf, total));
    if (wr == PICOKEYS_ERR_NO_MEMORY) {
        return INDEX_STORE_FULL;
    }
    if (wr != PICOKEYS_OK) {
        return INDEX_STORE_BAD;
    }
    if (!flash_commit_sync(INDEX_COMMIT_TIMEOUT_MS)) {
        return INDEX_STORE_BAD;
    }
    return INDEX_STORE_OK;
}

int index_store_delete(uint8_t entry_type, const uint8_t record_id[INDEX_RECORD_ID_LEN]) {
    uint16_t slot;
    file_t *ef;

    if (record_id == NULL) {
        return INDEX_STORE_BAD;
    }
    if (find_key(entry_type, record_id, &slot) != INDEX_STORE_OK) {
        return INDEX_STORE_NOT_FOUND;
    }
    ef = file_search(slot_fid(slot));
    if (ef == NULL || !file_has_data(ef)) {
        return INDEX_STORE_NOT_FOUND;
    }
    file_delete(ef);
    return INDEX_STORE_OK;
}

int index_store_get(uint8_t entry_type, const uint8_t record_id[INDEX_RECORD_ID_LEN],
    uint8_t *out, uint16_t out_max, uint16_t *out_len) {
    uint16_t slot;
    index_rec_t rec;
    const uint8_t *raw;
    uint16_t raw_len;

    if (record_id == NULL || out == NULL || out_len == NULL) {
        return INDEX_STORE_BAD;
    }
    if (find_key(entry_type, record_id, &slot) != INDEX_STORE_OK) {
        return INDEX_STORE_NOT_FOUND;
    }
    raw = slot_raw(slot, &rec, &raw_len);
    if (raw == NULL) {
        return INDEX_STORE_NOT_FOUND;
    }
    if (raw_len > out_max) {
        return INDEX_STORE_BAD;
    }
    memcpy(out, raw, raw_len);
    *out_len = raw_len;
    return INDEX_STORE_OK;
}

bool index_store_next(uint16_t start_slot, uint16_t *slot_out, index_rec_t *rec,
    const uint8_t **raw, uint16_t *raw_len) {
    uint16_t slot;
    const uint8_t *p;
    uint16_t len;
    index_rec_t local;

    if (slot_out == NULL || rec == NULL) {
        return false;
    }
    for (slot = start_slot; slot < INDEX_SLOT_MAX; slot++) {
        p = slot_raw(slot, &local, &len);
        if (p == NULL) {
            continue;
        }
        *slot_out = slot;
        *rec = local;
        if (raw != NULL) {
            *raw = p;
        }
        if (raw_len != NULL) {
            *raw_len = len;
        }
        return true;
    }
    return false;
}
