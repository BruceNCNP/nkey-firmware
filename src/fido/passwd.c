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

#include "maintenance.h"
#include "index_store.h"
#include "passwd_store.h"
#include "picokeys.h"
#include "apdu.h"
#include "button.h"
#include "random.h"
#include "usb.h"
#include "byte_array.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "bsp/board.h"
#endif
#ifndef ENABLE_EMULATION
#include "hid/ctap_hid.h"
#endif

#include <string.h>

#define PASSWD_CLA 0x81
#define PASSWD_INS 0x22
#define PASSWD_P1_BEGIN 0x01
#define PASSWD_P1_EXCHANGE 0x02
#define PASSWD_P1_END 0x03
#define PASSWD_P1_WRITE 0x10
#define PASSWD_P1_TYPE 0x20
#define PASSWD_P1_LIST 0x30
#define PASSWD_P1_DELETE 0x31
#define PASSWD_P1_MAINT_OPEN 0x40
#define PASSWD_P1_MAINT_CLOSE 0x41
#define PASSWD_P1_MAINT_STATUS 0x42
#define PASSWD_SESSION_MS 300000u
#define PASSWD_NONCE_MAX 128u
#define PASSWD_LIST_MAX 1024u
#define PASSWD_PLAIN_MAX 512u

static const char session_info[] = "nkey-passwd-v1-aes256gcm";

static struct {
    bool salt_valid;
    bool ready;
    uint32_t deadline;
    uint8_t salt[8];
    uint8_t key[32];
    uint8_t nonces[PASSWD_NONCE_MAX][12];
    uint8_t nonce_count;
} session;

typedef struct {
    const uint8_t *id;
    const uint8_t *name;
    uint8_t name_len;
    const uint8_t *display;
    uint8_t display_len;
    const uint8_t *password;
    uint8_t password_len;
} passwd_fields_t;

static int passwd_process_apdu(void);
static int passwd_unload(void);

static const uint8_t passwd_aid[] = {
    8,
    0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x22
};

static void session_clear(void) {
    mbedtls_platform_zeroize(&session, sizeof(session));
}

static bool session_alive(void) {
    if (!session.ready) {
        return false;
    }
    if ((int32_t)(board_millis() - session.deadline) >= 0) {
        session_clear();
        return false;
    }
    return true;
}

static bool nonce_seen(const uint8_t nonce[12]) {
    for (uint8_t i = 0; i < session.nonce_count; i++) {
        if (memcmp(session.nonces[i], nonce, 12) == 0) {
            return true;
        }
    }
    return false;
}

static int nonce_remember(const uint8_t nonce[12]) {
    if (session.nonce_count >= PASSWD_NONCE_MAX) {
        return -1;
    }
    memcpy(session.nonces[session.nonce_count], nonce, 12);
    session.nonce_count++;
    return 0;
}

static bool passwd_wait_button(void) {
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

static int parse_tlv(const uint8_t *plain, uint16_t len, passwd_fields_t *out) {
    memset(out, 0, sizeof(*out));
    uint16_t pos = 0;
    for (uint8_t tag = 0x01; tag <= 0x04; tag++) {
        if ((uint16_t)(pos + 2u) > len) {
            return -1;
        }
        if (plain[pos] != tag) {
            return -1;
        }
        uint8_t field_len = plain[pos + 1];
        pos = (uint16_t)(pos + 2u);
        if ((uint16_t)(pos + field_len) > len) {
            return -1;
        }
        const uint8_t *value = plain + pos;
        if (tag == 0x01) {
            if (field_len != 8) {
                return -1;
            }
            out->id = value;
        }
        else if (tag == 0x02 || tag == 0x03) {
            for (uint8_t i = 0; i < field_len; i++) {
                if (value[i] <= 0x1f) {
                    return -1;
                }
            }
            if (tag == 0x02) {
                out->name = value;
                out->name_len = field_len;
            }
            else {
                out->display = value;
                out->display_len = field_len;
            }
        }
        else {
            if (field_len < 1 || field_len > 254) {
                return -1;
            }
            for (uint8_t i = 0; i < field_len; i++) {
                if (value[i] >= 0x80) {
                    return -1;
                }
            }
            out->password = value;
            out->password_len = field_len;
        }
        pos = (uint16_t)(pos + field_len);
    }
    if (pos != len || out->id == NULL || out->password == NULL) {
        return -1;
    }
    return 0;
}

static int transport_decrypt(uint16_t slot, const uint8_t nonce[12], const uint8_t *ct,
    uint16_t ct_len, const uint8_t tag[16], uint8_t *plain) {
    uint8_t aad[6] = { 0x81, 0x22, 0x10, 0x00, 0, 0 };
    put_uint16_be(slot, aad + 4);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session.key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, ct_len, nonce, 12, aad, sizeof(aad), tag, 16, ct, plain);
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(aad, sizeof(aad));
    return ret;
}

static int cmd_begin(void) {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    if (!passwd_store_ready()) {
        return SW_EXEC_ERROR();
    }
    session_clear();
    if (random_fill_buffer(BYTE_ARRAY(session.salt, sizeof(session.salt))) != 0) {
        session_clear();
        return SW_EXEC_ERROR();
    }
    session.salt_valid = true;
    uint8_t q[65];
    if (passwd_store_public_key(q) != PASSWD_STORE_OK) {
        session_clear();
        return SW_EXEC_ERROR();
    }
    res_APDU[0] = 0x01;
    memcpy(res_APDU + 1, session.salt, sizeof(session.salt));
    memcpy(res_APDU + 9, q, sizeof(q));
    put_uint16_be(passwd_store_slot_max(), res_APDU + 74);
    res_APDU_size = 76;
    mbedtls_platform_zeroize(q, sizeof(q));
    return SW_OK();
}

static int cmd_exchange(void) {
    if (apdu.nc != 65) {
        return SW_WRONG_LENGTH();
    }
    if (!session.salt_valid) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t shared[32];
    uint8_t key[32];
    uint8_t digest[32];
    mbedtls_platform_zeroize(shared, sizeof(shared));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(digest, sizeof(digest));
    int store_rc = passwd_store_ecdh(apdu.data, shared);
    int sw;
    if (store_rc == PASSWD_STORE_BAD) {
        sw = SW_INCORRECT_PARAMS();
    }
    else if (store_rc != PASSWD_STORE_OK) {
        sw = SW_EXEC_ERROR();
    }
    else {
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (md == NULL || mbedtls_hkdf(md, session.salt, sizeof(session.salt), shared, sizeof(shared),
                (const uint8_t *)session_info, sizeof(session_info) - 1u, key, sizeof(key)) != 0 ||
            mbedtls_sha256(key, sizeof(key), digest, 0) != 0) {
            sw = SW_EXEC_ERROR();
        }
        else {
            memcpy(session.key, key, sizeof(key));
            session.ready = true;
            session.deadline = board_millis() + PASSWD_SESSION_MS;
            session.nonce_count = 0;
            mbedtls_platform_zeroize(session.nonces, sizeof(session.nonces));
            memcpy(res_APDU, digest, 8);
            res_APDU_size = 8;
            sw = SW_OK();
        }
    }
    mbedtls_platform_zeroize(shared, sizeof(shared));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(digest, sizeof(digest));
    return sw;
}

static int cmd_end(void) {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    session_clear();
    return SW_OK();
}

static int cmd_write(void) {
    if (!session_alive()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc < 30 || apdu.nc > 542) {
        return SW_WRONG_LENGTH();
    }
    uint16_t slot = get_uint16_be(apdu.data);
    if (slot >= passwd_store_slot_max()) {
        return SW_INCORRECT_PARAMS();
    }
    const uint8_t *nonce = apdu.data + 2;
    uint16_t ct_len = (uint16_t)(apdu.nc - 30u);
    const uint8_t *ct = apdu.data + 14;
    const uint8_t *tag = apdu.data + apdu.nc - 16u;
    if (nonce_seen(nonce)) {
        return SW_DATA_INVALID();
    }
    if (session.nonce_count >= PASSWD_NONCE_MAX) {
        return SW_FILE_FULL();
    }
    uint8_t plain[PASSWD_PLAIN_MAX];
    int sw;
    if (transport_decrypt(slot, nonce, ct, ct_len, tag, plain) != 0) {
        sw = SW_DATA_INVALID();
    }
    else {
        passwd_fields_t fields;
        if (parse_tlv(plain, ct_len, &fields) != 0) {
            sw = SW_INCORRECT_PARAMS();
        }
        else if (!maintenance_skip_button() && !passwd_wait_button()) {
            sw = SW_CONDITIONS_NOT_SATISFIED();
        }
        else {
            int store_rc = passwd_store_put(slot, plain, ct_len);
            if (store_rc == PASSWD_STORE_FULL) {
                sw = SW_FILE_FULL();
            }
            else if (store_rc != PASSWD_STORE_OK) {
                sw = SW_EXEC_ERROR();
            }
            else if (nonce_remember(nonce) != 0) {
                sw = SW_FILE_FULL();
            }
            else {
                index_sync_arm();
                sw = SW_OK();
            }
        }
    }
    mbedtls_platform_zeroize(plain, sizeof(plain));
    return sw;
}

static void passwd_type(const uint8_t *data, uint16_t len) {
#ifdef ENABLE_EMULATION
    (void)data;
    (void)len;
#else
    add_keyboard_buffer(CONST_BYTE_ARRAY(data, len), true);
#endif
}

static int cmd_type(void) {
    if (apdu.nc != 3) {
        return SW_WRONG_LENGTH();
    }
    uint16_t slot = get_uint16_be(apdu.data);
    uint8_t flags = apdu.data[2];
    if (slot >= passwd_store_slot_max() || (flags & (uint8_t)~0x01) != 0) {
        return SW_INCORRECT_PARAMS();
    }
    if (!passwd_store_ready()) {
        return SW_EXEC_ERROR();
    }
    if (!passwd_store_exists(slot)) {
        return SW_DATA_INVALID();
    }
    if (!passwd_wait_button()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    uint8_t plain[PASSWD_PLAIN_MAX];
    uint8_t typed[255];
    uint16_t plain_len = 0;
    int sw;
    if (passwd_store_get(slot, plain, sizeof(plain), &plain_len) != PASSWD_STORE_OK) {
        sw = SW_EXEC_ERROR();
    }
    else {
        passwd_fields_t fields;
        if (parse_tlv(plain, plain_len, &fields) != 0) {
            sw = SW_EXEC_ERROR();
        }
        else {
            uint8_t typed_len = fields.password_len;
            memcpy(typed, fields.password, typed_len);
            if ((flags & 0x01) != 0) {
                typed[typed_len++] = 0x0d;
            }
            passwd_type(typed, typed_len);
            sw = SW_OK();
        }
    }
    mbedtls_platform_zeroize(typed, sizeof(typed));
    mbedtls_platform_zeroize(plain, sizeof(plain));
    return sw;
}

static int cmd_list(void) {
    if (apdu.nc != 2) {
        return SW_WRONG_LENGTH();
    }
    uint16_t start = get_uint16_be(apdu.data);
    if (start >= passwd_store_slot_max()) {
        return SW_INCORRECT_PARAMS();
    }
    if (!passwd_store_ready()) {
        return SW_EXEC_ERROR();
    }
    uint16_t count = 0;
    uint16_t pos = 5;
    uint8_t has_more = 0;
    uint16_t next_start = 0;
    uint8_t plain[PASSWD_PLAIN_MAX];
    for (uint16_t slot = start; slot < passwd_store_slot_max(); slot++) {
        if (!passwd_store_exists(slot)) {
            continue;
        }
        uint16_t plain_len = 0;
        if (passwd_store_get(slot, plain, sizeof(plain), &plain_len) != PASSWD_STORE_OK) {
            mbedtls_platform_zeroize(plain, sizeof(plain));
            continue;
        }
        passwd_fields_t fields;
        if (parse_tlv(plain, plain_len, &fields) != 0) {
            mbedtls_platform_zeroize(plain, sizeof(plain));
            continue;
        }
        uint16_t item_len = (uint16_t)(2u + 8u + 1u + fields.name_len + 1u + fields.display_len);
        if ((uint32_t)pos + item_len > PASSWD_LIST_MAX) {
            if (count == 0) {
                mbedtls_platform_zeroize(plain, sizeof(plain));
                return SW_EXEC_ERROR();
            }
            has_more = 1;
            next_start = slot;
            mbedtls_platform_zeroize(plain, sizeof(plain));
            break;
        }
        put_uint16_be(slot, res_APDU + pos);
        pos = (uint16_t)(pos + 2u);
        memcpy(res_APDU + pos, fields.id, 8);
        pos = (uint16_t)(pos + 8u);
        res_APDU[pos++] = fields.name_len;
        if (fields.name_len > 0) {
            memcpy(res_APDU + pos, fields.name, fields.name_len);
            pos = (uint16_t)(pos + fields.name_len);
        }
        res_APDU[pos++] = fields.display_len;
        if (fields.display_len > 0) {
            memcpy(res_APDU + pos, fields.display, fields.display_len);
            pos = (uint16_t)(pos + fields.display_len);
        }
        count++;
        mbedtls_platform_zeroize(plain, sizeof(plain));
    }
    res_APDU[0] = has_more;
    put_uint16_be(next_start, res_APDU + 1);
    put_uint16_be(count, res_APDU + 3);
    res_APDU_size = pos;
    mbedtls_platform_zeroize(plain, sizeof(plain));
    return SW_OK();
}

static int cmd_delete(void) {
    if (apdu.nc != 2) {
        return SW_WRONG_LENGTH();
    }
    uint16_t slot = get_uint16_be(apdu.data);
    if (slot >= passwd_store_slot_max()) {
        return SW_INCORRECT_PARAMS();
    }
    if (!passwd_store_ready()) {
        return SW_EXEC_ERROR();
    }
    if (!passwd_store_exists(slot)) {
        return SW_DATA_INVALID();
    }
    if (!maintenance_skip_button() && !passwd_wait_button()) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (passwd_store_delete(slot) != PASSWD_STORE_OK) {
        return SW_EXEC_ERROR();
    }
    index_sync_arm();
    return SW_OK();
}

static int reply_remaining(void) {
    put_uint16_be(maintenance_remaining_s(), res_APDU);
    res_APDU_size = 2;
    return SW_OK();
}

static int cmd_maintain_open(void) {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    if (!maintenance_active()) {
        if (!passwd_wait_button()) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        maintenance_open();
    }
    return reply_remaining();
}

static int cmd_maintain_close(void) {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    maintenance_close();
    return SW_OK();
}

static int cmd_maintain_status(void) {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    return reply_remaining();
}

static int passwd_select(app_t *a, uint8_t force) {
    (void)force;
    a->process_apdu = passwd_process_apdu;
    a->unload = passwd_unload;
    res_APDU_size = 0;
    passwd_store_init();
    return PICOKEYS_OK;
}

INITIALIZER(passwd_ctor) {
    register_app(passwd_select, passwd_aid);
}

static int passwd_unload(void) {
    session_clear();
    return PICOKEYS_OK;
}

static int passwd_process_apdu(void) {
    res_APDU_size = 0;
    if (CLA(apdu) != PASSWD_CLA) {
        return sw_cla_not_supported(CLA_REJECT_PASSWD);
    }
    if (INS(apdu) != PASSWD_INS) {
        return SW_INS_NOT_SUPPORTED();
    }
    if (P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    switch (P1(apdu)) {
        case PASSWD_P1_BEGIN:
            return cmd_begin();
        case PASSWD_P1_EXCHANGE:
            return cmd_exchange();
        case PASSWD_P1_END:
            return cmd_end();
        case PASSWD_P1_WRITE:
            return cmd_write();
        case PASSWD_P1_TYPE:
            return cmd_type();
        case PASSWD_P1_LIST:
            return cmd_list();
        case PASSWD_P1_DELETE:
            return cmd_delete();
        case PASSWD_P1_MAINT_OPEN:
            return cmd_maintain_open();
        case PASSWD_P1_MAINT_CLOSE:
            return cmd_maintain_close();
        case PASSWD_P1_MAINT_STATUS:
            return cmd_maintain_status();
        default:
            return SW_INCORRECT_P1P2();
    }
}
