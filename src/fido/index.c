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
#include "picokeys.h"
#include "apdu.h"
#include "button.h"
#include "usb.h"
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "bsp/board.h"
#endif
#ifndef ENABLE_EMULATION
#include "hid/ctap_hid.h"
#endif

#include <string.h>

#define INDEX_CLA 0x82
#define INDEX_INS 0x30
#define INDEX_P1_PUT 0x10
#define INDEX_P1_DEL 0x20
#define INDEX_P1_LIST 0x30
#define INDEX_P1_GET 0x31
#define INDEX_LIST_MAX 1024u

static int index_process_apdu(void);
static int index_unload(void);

/* Length-prefixed AID (aid[0] = len), same layout as passwd_aid. */
static const uint8_t index_aid[] = {
    8,
    0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x23
};

static bool index_wait_button(void) {
#ifdef ENABLE_EMULATION
    return true;
#else
#if defined(PICO_PLATFORM)
    if (get_core_num() == 0) {
        return false;
    }
#elif defined(ESP_PLATFORM)
    if (xTaskGetCurrentTaskHandle() == hcore0) {
        return false;
    }
#endif
    bool previous_force = force_button_wait;
#ifdef FORCE_BUTTON_WAIT
    force_button_wait = true;
#endif
    button_set_wait_feedback(true);
    uint32_t event = EV_PRESS_BUTTON_WITH_TIMEOUT(button_timeout_seconds());
    queue_add_blocking(&card_to_usb_q, &event);
    int waited = button_wait_core_event(&event);
    force_button_wait = previous_force;
    button_set_wait_feedback(true);
    return waited == 0;
#endif
}

static bool ensure_write_auth(void) {
    if (index_sync_allow_write()) {
        return true;
    }
    return index_wait_button();
}

static int cmd_put(void) {
    const uint8_t *data = apdu.data;
    uint8_t entry_type;
    const uint8_t *record_id;
    const uint8_t *tlv;
    uint16_t tlv_len;
    int rc;

    if (apdu.nc < (1u + INDEX_RECORD_ID_LEN)) {
        return SW_WRONG_LENGTH();
    }
    entry_type = data[0];
    record_id = data + 1;
    tlv = data + 1 + INDEX_RECORD_ID_LEN;
    tlv_len = (uint16_t)(apdu.nc - (1u + INDEX_RECORD_ID_LEN));
    if (!index_store_tlv_ok(tlv, tlv_len)) {
        return SW_INCORRECT_PARAMS();
    }
    if (!ensure_write_auth()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    rc = index_store_put(entry_type, record_id, tlv, tlv_len);
    if (rc == INDEX_STORE_FULL) {
        return SW_FILE_FULL();
    }
    if (rc != INDEX_STORE_OK) {
        return SW_EXEC_ERROR();
    }
    index_sync_consume();
    return SW_OK();
}

static int cmd_del(void) {
    const uint8_t *data = apdu.data;
    int rc;

    if (apdu.nc != (1u + INDEX_RECORD_ID_LEN)) {
        return SW_WRONG_LENGTH();
    }
    if (!ensure_write_auth()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    rc = index_store_delete(data[0], data + 1);
    if (rc == INDEX_STORE_NOT_FOUND) {
        return SW_FILE_NOT_FOUND();
    }
    if (rc != INDEX_STORE_OK) {
        return SW_EXEC_ERROR();
    }
    index_sync_consume();
    return SW_OK();
}

static int cmd_list(void) {
    uint16_t start;
    uint16_t slot;
    uint16_t pos = 3;
    uint16_t next = INDEX_SLOT_MAX;
    uint8_t has_more = 0;
    index_rec_t rec;
    const uint8_t *raw;
    uint16_t raw_len;

    if (apdu.nc != 2) {
        return SW_WRONG_LENGTH();
    }
    start = get_uint16_be(apdu.data);
    if (start >= INDEX_SLOT_MAX) {
        return SW_INCORRECT_PARAMS();
    }
    res_APDU[0] = 0;
    put_uint16_be(INDEX_SLOT_MAX, res_APDU + 1);

    while (index_store_next(start, &slot, &rec, &raw, &raw_len)) {
        uint16_t need = (uint16_t)(2u + raw_len);
        if ((uint16_t)(pos + need) > INDEX_LIST_MAX) {
            has_more = 1;
            next = slot;
            break;
        }
        put_uint16_be(slot, res_APDU + pos);
        pos = (uint16_t)(pos + 2u);
        memcpy(res_APDU + pos, raw, raw_len);
        pos = (uint16_t)(pos + raw_len);
        start = (uint16_t)(slot + 1u);
        if (start >= INDEX_SLOT_MAX) {
            next = INDEX_SLOT_MAX;
            break;
        }
        next = start;
    }
    res_APDU[0] = has_more;
    put_uint16_be(next, res_APDU + 1);
    res_APDU_size = pos;
    return SW_OK();
}

static int cmd_get(void) {
    uint8_t buf[INDEX_RECORD_MAX];
    uint16_t out_len = 0;
    int rc;

    if (apdu.nc != (1u + INDEX_RECORD_ID_LEN)) {
        return SW_WRONG_LENGTH();
    }
    rc = index_store_get(apdu.data[0], apdu.data + 1, buf, sizeof(buf), &out_len);
    if (rc == INDEX_STORE_NOT_FOUND) {
        return SW_FILE_NOT_FOUND();
    }
    if (rc != INDEX_STORE_OK) {
        return SW_EXEC_ERROR();
    }
    memcpy(res_APDU, buf, out_len);
    res_APDU_size = out_len;
    return SW_OK();
}

static int index_select(app_t *a, uint8_t force) {
    (void)force;
    a->process_apdu = index_process_apdu;
    a->unload = index_unload;
    res_APDU_size = 0;
    return PICOKEYS_OK;
}

INITIALIZER(index_ctor) {
    register_app(index_select, index_aid);
}

static int index_unload(void) {
    return PICOKEYS_OK;
}

static int index_process_apdu(void) {
    res_APDU_size = 0;
    if (CLA(apdu) != INDEX_CLA) {
        return sw_cla_not_supported(CLA_REJECT_INDEX);
    }
    if (INS(apdu) != INDEX_INS) {
        return SW_INS_NOT_SUPPORTED();
    }
    if (P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    switch (P1(apdu)) {
        case INDEX_P1_PUT:
            return cmd_put();
        case INDEX_P1_DEL:
            return cmd_del();
        case INDEX_P1_LIST:
            return cmd_list();
        case INDEX_P1_GET:
            return cmd_get();
        default:
            return SW_INCORRECT_P1P2();
    }
}
