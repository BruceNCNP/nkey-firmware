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

#include "passwd_store.h"
#include "picokeys.h"
#include "file.h"
#include "flash.h"
#include "random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#include <string.h>

/* Same timeout as PIN_RETRY_COMMIT_TIMEOUT_MS in cbor_client_pin.c. */
#define PASSWD_COMMIT_TIMEOUT_MS 500u
#define PASSWD_PLAIN_MAX 512u
#define PASSWD_KEY_LEN 32u

_Static_assert(PASSWD_SLOT_MAX == 55u, "password slot count is fixed at 55");
_Static_assert(PASSWD_SLOT_MAX <= 255u, "slot fids must stay below the key file");
_Static_assert((uint16_t)(PASSWD_FID_BASE + PASSWD_SLOT_MAX - 1u) == 0xE436u, "last slot fid");
_Static_assert(PASSWD_KEY_FID == 0xE4FFu, "storage key fid");
_Static_assert((uint16_t)(PASSWD_FID_BASE + PASSWD_SLOT_MAX - 1u) < PASSWD_KEY_FID,
    "key fid collides with a slot");
_Static_assert(PASSWD_RECORD_MAX == 548u, "password record size");

static uint8_t dev_priv[32];
static uint8_t dev_pub[65];
static uint8_t root_key[PASSWD_KEY_LEN];
static bool ready;
static bool key_persist_failed;

static const uint8_t slot_salt[16] = {
    'n', 'k', 'e', 'y', '-', 'p', 'w', '-', 's', 'l', 'o', 't', '-', 's', '1', 0x00
};
static const char slot_info[] = "nkey-passwd-slot-enc-v1";

typedef struct {
    uint16_t slot;
    uint16_t payload_len;
    uint16_t total;
    uint8_t state;
} passwd_rec_t;

static uint16_t slot_fid(uint16_t slot) {
    return (uint16_t)(PASSWD_FID_BASE + slot);
}

static bool rec_parse(const uint8_t *p, uint32_t len, passwd_rec_t *rec) {
    if (p == NULL || len < 8u) {
        return false;
    }
    if (p[0] != 0x50 || p[1] != 0x57 || p[2] != 0x01) {
        return false;
    }
    uint16_t slot = get_uint16_be(p + 4);
    uint16_t payload_len = get_uint16_be(p + 6);
    if (payload_len < 28u || payload_len > 540u) {
        return false;
    }
    uint32_t total = 8u + payload_len;
    if (total > len || total > PASSWD_RECORD_MAX || slot >= PASSWD_SLOT_MAX) {
        return false;
    }
    rec->slot = slot;
    rec->payload_len = payload_len;
    rec->total = (uint16_t)total;
    rec->state = p[2];
    return true;
}

static const uint8_t *slot_record(uint16_t slot, passwd_rec_t *rec) {
    if (slot >= PASSWD_SLOT_MAX) {
        return NULL;
    }
    file_t *ef = file_search(slot_fid(slot));
    if (!file_has_data(ef)) {
        return NULL;
    }
    const uint8_t *p = file_get_data(ef);
    if (!rec_parse(p, file_get_size(ef), rec) || rec->slot != slot) {
        return NULL;
    }
    return p;
}

static int load_or_create_root_key(void) {
    file_t *ef;
    const uint8_t *stored;

    if (key_persist_failed) {
        return -1;
    }
    ef = file_search(PASSWD_KEY_FID);
    if (ef != NULL && file_has_data(ef)) {
        if (file_get_size(ef) != PASSWD_KEY_LEN) {
            return -1;
        }
        stored = file_get_data(ef);
        if (stored == NULL) {
            return -1;
        }
        memcpy(root_key, stored, PASSWD_KEY_LEN);
        return 0;
    }
    if (random_fill_buffer(BYTE_ARRAY(root_key, PASSWD_KEY_LEN)) != 0) {
        mbedtls_platform_zeroize(root_key, sizeof(root_key));
        return -1;
    }
    ef = file_new(PASSWD_KEY_FID);
    if (ef == NULL) {
        mbedtls_platform_zeroize(root_key, sizeof(root_key));
        return -1;
    }
    if (file_put_data(ef, CONST_BYTE_ARRAY(root_key, PASSWD_KEY_LEN)) != PICOKEYS_OK) {
        mbedtls_platform_zeroize(root_key, sizeof(root_key));
        return -1;
    }
    if (!flash_commit_sync(PASSWD_COMMIT_TIMEOUT_MS) || file_get_size(ef) != PASSWD_KEY_LEN ||
        file_get_data(ef) == NULL) {
        key_persist_failed = true;
        mbedtls_platform_zeroize(root_key, sizeof(root_key));
        return -1;
    }
    return 0;
}

static int slot_enc_key(uint8_t key[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return PASSWD_STORE_CRYPTO;
    }
    if (mbedtls_hkdf(md, slot_salt, sizeof(slot_salt), root_key, sizeof(root_key),
            (const uint8_t *)slot_info, sizeof(slot_info) - 1u, key, 32) != 0) {
        return PASSWD_STORE_CRYPTO;
    }
    return PASSWD_STORE_OK;
}

static void storage_aad(uint16_t slot, uint8_t aad[10]) {
    memcpy(aad, "PWSLOTv1", 8);
    put_uint16_be(slot, aad + 8);
}

static int gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t aad[10],
    const uint8_t *plain, uint16_t plain_len, uint8_t *ct, uint8_t tag[16]) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len, nonce, 12,
            aad, 10, plain, ct, 16, tag);
    }
    mbedtls_gcm_free(&gcm);
    return ret;
}

static int gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t aad[10],
    const uint8_t *ct, uint16_t ct_len, const uint8_t tag[16], uint8_t *plain) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, ct_len, nonce, 12, aad, 10, tag, 16, ct, plain);
    }
    mbedtls_gcm_free(&gcm);
    return ret;
}

static int store_record(uint16_t slot, const uint8_t *rec, uint16_t total) {
    file_t *ef = file_new(slot_fid(slot));
    int wr;
    if (ef == NULL) {
        return PASSWD_STORE_FULL;
    }
    wr = file_put_data(ef, CONST_BYTE_ARRAY(rec, total));
    if (wr == PICOKEYS_ERR_NO_MEMORY) {
        return PASSWD_STORE_FULL;
    }
    if (wr != PICOKEYS_OK) {
        return PASSWD_STORE_BAD;
    }
    if (!flash_commit_sync(PASSWD_COMMIT_TIMEOUT_MS)) {
        return PASSWD_STORE_BAD;
    }
    return PASSWD_STORE_OK;
}

void passwd_store_init(void) {
    mbedtls_ecp_keypair key;
    size_t olen = 0;
    int ret;

    if (ready) {
        return;
    }
    mbedtls_platform_zeroize(dev_priv, sizeof(dev_priv));
    mbedtls_platform_zeroize(dev_pub, sizeof(dev_pub));
    mbedtls_platform_zeroize(root_key, sizeof(root_key));
    if (load_or_create_root_key() != 0) {
        mbedtls_platform_zeroize(root_key, sizeof(root_key));
        return;
    }

    mbedtls_ecp_keypair_init(&key);
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &key, random_fill_iterator, NULL);
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&key.MBEDTLS_PRIVATE(grp), &key.MBEDTLS_PRIVATE(Q),
            MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, dev_pub, sizeof(dev_pub));
    }
    if (ret == 0 && olen == sizeof(dev_pub)) {
        ret = mbedtls_mpi_write_binary(&key.MBEDTLS_PRIVATE(d), dev_priv, sizeof(dev_priv));
    }
    else {
        ret = -1;
    }
    mbedtls_ecp_keypair_free(&key);
    if (ret != 0) {
        mbedtls_platform_zeroize(dev_priv, sizeof(dev_priv));
        mbedtls_platform_zeroize(dev_pub, sizeof(dev_pub));
        mbedtls_platform_zeroize(root_key, sizeof(root_key));
        return;
    }
    ready = true;
}

bool passwd_store_ready(void) {
    return ready;
}

uint16_t passwd_store_slot_max(void) {
    return (uint16_t)PASSWD_SLOT_MAX;
}

int passwd_store_public_key(uint8_t q[65]) {
    if (!ready) {
        return PASSWD_STORE_CRYPTO;
    }
    memcpy(q, dev_pub, sizeof(dev_pub));
    return PASSWD_STORE_OK;
}

int passwd_store_ecdh(const uint8_t q_host[65], uint8_t shared[32]) {
    if (!ready) {
        return PASSWD_STORE_CRYPTO;
    }
    mbedtls_ecp_keypair ours;
    mbedtls_ecp_point peer;
    mbedtls_mpi z;
    mbedtls_ecp_keypair_init(&ours);
    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&z);
    int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ours, dev_priv, sizeof(dev_priv));
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&ours.MBEDTLS_PRIVATE(grp), &peer, q_host, 65);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_pubkey(&ours.MBEDTLS_PRIVATE(grp), &peer);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_compute_shared(&ours.MBEDTLS_PRIVATE(grp), &z, &peer,
            &ours.MBEDTLS_PRIVATE(d), random_fill_iterator, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&z, shared, 32);
    }
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_keypair_free(&ours);
    if (ret != 0) {
        mbedtls_platform_zeroize(shared, 32);
        return PASSWD_STORE_BAD;
    }
    uint8_t nonzero = 0;
    for (size_t i = 0; i < 32; i++) {
        nonzero |= shared[i];
    }
    if (nonzero == 0) {
        mbedtls_platform_zeroize(shared, 32);
        return PASSWD_STORE_BAD;
    }
    return PASSWD_STORE_OK;
}

bool passwd_store_exists(uint16_t slot) {
    passwd_rec_t rec;
    return ready && slot_record(slot, &rec) != NULL;
}

int passwd_store_put(uint16_t slot, const uint8_t *plain, uint16_t plain_len) {
    uint8_t rec[PASSWD_RECORD_MAX];
    uint8_t key[32];
    uint8_t aad[10];
    uint16_t payload_len;
    uint16_t total;
    int rc;

    if (!ready) {
        return PASSWD_STORE_CRYPTO;
    }
    if (slot >= PASSWD_SLOT_MAX || plain == NULL || plain_len > PASSWD_PLAIN_MAX) {
        return PASSWD_STORE_BAD;
    }
    payload_len = (uint16_t)(12u + plain_len + 16u);
    total = (uint16_t)(8u + payload_len);
    if (total > PASSWD_RECORD_MAX) {
        return PASSWD_STORE_BAD;
    }
    memset(rec, 0, sizeof(rec));
    rec[0] = 0x50;
    rec[1] = 0x57;
    rec[2] = 0x01;
    rec[3] = 0x00;
    put_uint16_be(slot, rec + 4);
    put_uint16_be(payload_len, rec + 6);
    rc = slot_enc_key(key);
    if (rc == PASSWD_STORE_OK && random_fill_buffer(BYTE_ARRAY(rec + 8, 12)) != 0) {
        rc = PASSWD_STORE_CRYPTO;
    }
    if (rc == PASSWD_STORE_OK) {
        storage_aad(slot, aad);
        if (gcm_encrypt(key, rec + 8, aad, plain, plain_len, rec + 20, rec + 20 + plain_len) != 0) {
            rc = PASSWD_STORE_CRYPTO;
        }
    }
    if (rc == PASSWD_STORE_OK) {
        rc = store_record(slot, rec, total);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(aad, sizeof(aad));
    mbedtls_platform_zeroize(rec, sizeof(rec));
    return rc;
}

int passwd_store_get(uint16_t slot, uint8_t *plain, uint16_t plain_max, uint16_t *plain_len) {
    passwd_rec_t rec;
    const uint8_t *p;
    uint16_t ct_len;
    uint8_t key[32];
    uint8_t aad[10];
    int rc;

    if (!ready) {
        return PASSWD_STORE_CRYPTO;
    }
    p = slot_record(slot, &rec);
    if (p == NULL || plain == NULL || plain_len == NULL) {
        return PASSWD_STORE_NOT_FOUND;
    }
    ct_len = (uint16_t)(rec.payload_len - 28u);
    if (ct_len > plain_max) {
        return PASSWD_STORE_BAD;
    }
    rc = slot_enc_key(key);
    if (rc == PASSWD_STORE_OK) {
        storage_aad(slot, aad);
        if (gcm_decrypt(key, p + 8, aad, p + 20, ct_len, p + 20 + ct_len, plain) != 0) {
            mbedtls_platform_zeroize(plain, plain_max);
            rc = PASSWD_STORE_CRYPTO;
        }
        else {
            *plain_len = ct_len;
        }
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(aad, sizeof(aad));
    return rc;
}

int passwd_store_delete(uint16_t slot) {
    file_t *ef;

    if (!ready) {
        return PASSWD_STORE_CRYPTO;
    }
    if (slot >= PASSWD_SLOT_MAX) {
        return PASSWD_STORE_NOT_FOUND;
    }
    ef = file_search(slot_fid(slot));
    if (!file_has_data(ef)) {
        return PASSWD_STORE_NOT_FOUND;
    }
    if (file_delete(ef) != PICOKEYS_OK) {
        return PASSWD_STORE_BAD;
    }
    return PASSWD_STORE_OK;
}
