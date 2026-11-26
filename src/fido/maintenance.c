/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "maintenance.h"
#include "picokeys.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif

#define MAINTENANCE_IDLE_MS 3000u
#define MAINTENANCE_MAX_MS 120000u

static bool open_flag = false;
static uint32_t opened_at = 0;
static uint32_t deadline = 0;

static void maintenance_clear(void) {
    open_flag = false;
    opened_at = 0;
    deadline = 0;
}

bool maintenance_active(void) {
    if (!open_flag) {
        return false;
    }
    uint32_t now = board_millis();
    if ((int32_t)(now - deadline) >= 0 || (int32_t)(now - (opened_at + MAINTENANCE_MAX_MS)) >= 0) {
        maintenance_clear();
        return false;
    }
    return true;
}

void maintenance_open(void) {
    uint32_t now = board_millis();
    open_flag = true;
    opened_at = now;
    deadline = now + MAINTENANCE_IDLE_MS;
}

void maintenance_close(void) {
    maintenance_clear();
}

uint16_t maintenance_remaining_s(void) {
    if (!maintenance_active()) {
        return 0;
    }
    uint32_t left = deadline - board_millis();
    uint32_t seconds = left / 1000u;
    if (seconds == 0 && left > 0) {
        seconds = 1;
    }
    if (seconds > 65535u) {
        seconds = 65535u;
    }
    return (uint16_t)seconds;
}

bool maintenance_skip_button(void) {
    if (!maintenance_active()) {
        return false;
    }
    uint32_t now = board_millis();
    uint32_t next = now + MAINTENANCE_IDLE_MS;
    uint32_t cap = opened_at + MAINTENANCE_MAX_MS;
    if ((int32_t)(next - cap) > 0) {
        next = cap;
    }
    deadline = next;
    return true;
}
