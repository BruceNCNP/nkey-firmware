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

#ifndef BUTTON_H
#define BUTTON_H

#include <stdint.h>
#include <stdbool.h>

#if defined(ESP_PLATFORM)
#define BOOT_PIN GPIO_NUM_0
#endif

typedef enum {
    BUTTON_EV_PRESSED,
    BUTTON_EV_TIMEOUT,
    BUTTON_EV_CANCELLED,
    BUTTON_EV_NONE,
} button_event_t;

extern void button_wait_start(void);
extern void button_wait_poll(bool pressed);
/* Core 1: sleep until a button result. 0 pressed, 1 timeout, 2 cancelled.
 * EV_EXIT is put back for the card thread so card_exit() can finish. */
extern int button_wait_core_event(uint32_t *event);
extern volatile uint32_t button_pressed_duration;
extern void button_task(void);
extern volatile bool cancel_button;
extern bool touch_accept_button;
extern volatile bool force_button_wait;
extern uint32_t button_timeout_seconds(void);
extern void button_wait_start_timeout(uint32_t timeout_seconds);
extern void button_set_wait_feedback(bool paint);

extern int (*button_pressed_cb)(uint8_t);

extern bool is_req_button_pending(void);

#endif // BUTTON_H
