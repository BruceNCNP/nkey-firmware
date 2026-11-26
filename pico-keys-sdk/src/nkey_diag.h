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

#ifndef _NKEY_DIAG_H_
#define _NKEY_DIAG_H_

#include "compat/compat.h"
#include "phy.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    DIAG_CMD_NONE = 0,
    DIAG_CMD_EXIT,
    DIAG_CMD_LED_STATIC,
    DIAG_CMD_LED_PATTERN,
    DIAG_CMD_TEMP_PHY,
} nkey_diag_cmd_t;

typedef struct {
    nkey_diag_cmd_t cmd;
    uint8_t color_mode;
    uint8_t pattern_id;
    phy_data_t temp_phy;
    uint32_t seq;
} nkey_diag_request_t;

/* Core 1 writes the command, then the sequence. Core 0 consumes it. */
uint32_t nkey_diag_post(nkey_diag_cmd_t cmd, uint8_t color_mode, uint8_t pattern_id, const phy_data_t *phy);
bool nkey_diag_take(nkey_diag_request_t *request);
void nkey_diag_mark_applied(uint32_t seq);
bool nkey_diag_wait(uint32_t seq);

#endif
