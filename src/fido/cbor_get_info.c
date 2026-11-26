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

#include "picokeys.h"
#include "ctap2_cbor.h"
#include "hid/ctap_hid.h"
#include "fido.h"
#include "ctap.h"
#include "apdu.h"

int cbor_get_info(void) {
    CborEncoder encoder, mapEncoder, arrayEncoder, mapEncoder2;
    CborError error = CborNoError;
    /* 0x01 versions, 0x02 extensions, 0x03 aaguid, 0x04 options,
     * 0x05 maxMsgSize, 0x06 pinUvAuthProtocols (button UV only),
     * 0x07 maxCredentialCountInList, 0x08 maxCredentialIdLength,
     * 0x09 transports, 0x0A algorithms. clientPin is omitted.
     * Button UV options also include credMgmt and pinUvAuthToken. */
    const bool button_uv = uvemu_is_button();
    const uint8_t lfields = button_uv ? 10 : 9;
    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, lfields));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 3));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "U2F_V2"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_0"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_1"));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 2));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "credProtect"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "hmac-secret"));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, aaguid, sizeof(aaguid)));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
    CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &arrayEncoder, button_uv ? 5 : 3));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "rk"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, !(get_opts() & FIDO2_OPT_NORK)));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "up"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "uv"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, button_uv));
    if (button_uv) {
        CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "credMgmt"));
        CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
        CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "pinUvAuthToken"));
        CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    }
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_MSG_SIZE));

    if (button_uv) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
        CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 1));
        CBOR_CHECK(cbor_encode_uint(&arrayEncoder, 1));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));
    }

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_CREDENTIAL_COUNT_IN_LIST));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_CRED_ID_LENGTH));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x09));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 2));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "usb"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "smart-card"));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));

    uint8_t curves = 3;
#ifdef MBEDTLS_EDDSA_C
    curves++;
#endif
#ifndef ENABLE_EMULATION
    if (phy_data.enabled_curves & PHY_CURVE_SECP256K1) {
#endif
        curves++;
#ifndef ENABLE_EMULATION
    }
#endif
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, curves));
    CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES256, &arrayEncoder, &mapEncoder2));
#ifdef MBEDTLS_EDDSA_C
    CBOR_CHECK(COSE_public_key(FIDO2_ALG_EDDSA, &arrayEncoder, &mapEncoder2));
#endif
    CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES384, &arrayEncoder, &mapEncoder2));
    CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES512, &arrayEncoder, &mapEncoder2));
#ifndef ENABLE_EMULATION
    if (phy_data.enabled_curves & PHY_CURVE_SECP256K1) {
#endif
        CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES256K, &arrayEncoder, &mapEncoder2));
#ifndef ENABLE_EMULATION
    }
#endif

    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));

err:
    if (error != CborNoError) {
        return -CTAP2_ERR_INVALID_CBOR;
    }
    res_APDU_size = (uint16_t)cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    return 0;
}
