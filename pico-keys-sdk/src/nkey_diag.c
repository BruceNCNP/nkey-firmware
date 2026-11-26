/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
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
#include "nkey_diag.h"
#include "pico_time.h"
#include <string.h>

#if defined(PICO_PLATFORM)
#include "hardware/sync.h"
#define nkey_diag_barrier() __dmb()
#elif defined(ESP_PLATFORM)
#define nkey_diag_barrier() __asm__ __volatile__("memw" ::: "memory")
#else
#define nkey_diag_barrier() do {} while (0)
#endif

typedef struct {
    volatile uint32_t seq;
    volatile uint32_t applied_seq;
    nkey_diag_cmd_t cmd;
    uint8_t color_mode;
    uint8_t pattern_id;
    phy_data_t temp_phy;
} nkey_led_mailbox_t;

static nkey_led_mailbox_t mailbox;

uint32_t nkey_diag_post(nkey_diag_cmd_t cmd, uint8_t color_mode, uint8_t pattern_id, const phy_data_t *phy) {
    mailbox.cmd = cmd;
    mailbox.color_mode = color_mode;
    mailbox.pattern_id = pattern_id;
    if (phy != NULL) {
        mailbox.temp_phy = *phy;
    }
    else {
        memset(&mailbox.temp_phy, 0, sizeof(mailbox.temp_phy));
    }
    nkey_diag_barrier();
    uint32_t seq = mailbox.seq + 1u;
    mailbox.seq = seq;
    return seq;
}

bool nkey_diag_take(nkey_diag_request_t *request) {
    static uint32_t last_seq = 0;
    uint32_t seq = mailbox.seq;
    if (seq == last_seq) {
        return false;
    }
    nkey_diag_barrier();
    request->cmd = mailbox.cmd;
    request->color_mode = mailbox.color_mode;
    request->pattern_id = mailbox.pattern_id;
    request->temp_phy = mailbox.temp_phy;
    request->seq = seq;
    last_seq = seq;
    return true;
}

void nkey_diag_mark_applied(uint32_t seq) {
    nkey_diag_barrier();
    mailbox.applied_seq = seq;
}

bool nkey_diag_wait(uint32_t seq) {
#if !defined(PICO_PLATFORM) && !defined(ESP_PLATFORM)
    (void)seq;
    return true;
#else
    uint32_t start = board_millis();
    for (;;) {
        nkey_diag_barrier();
        if (mailbox.applied_seq == seq) {
            return true;
        }
        if ((uint32_t)(board_millis() - start) > 500u) {
            return false;
        }
    }
#endif
}
