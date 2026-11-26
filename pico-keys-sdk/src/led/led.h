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

#ifndef _LED_H_
#define _LED_H_

#include <stdint.h>

enum {
    LED_COLOR_OFF = 0,
    LED_COLOR_RED,
    LED_COLOR_GREEN,
    LED_COLOR_BLUE,
    LED_COLOR_YELLOW,
    LED_COLOR_MAGENTA,
    LED_COLOR_CYAN,
    LED_COLOR_WHITE
};

#define MAX_BTNESS 15

extern void led_init(void);
extern void led_blinking_task(void);
const struct phy_data *led_hw_config(void);
extern void led_idle(void);
extern void led_steady(uint8_t color);
extern void led_steady_reinit(uint8_t color);
extern bool led_output_unchanged(bool gpio_present, uint8_t gpio, bool driver_present, uint8_t driver);
extern void led_usb_ready(void);
extern void led_authorization_wait(void);
extern void led_authorization_success(void);
extern void led_authorization_failure(void);

typedef struct {
    void (*init)(void);
    void (*set_color)(uint8_t color, uint32_t led_brightness, float progress);
} led_driver_t;

extern led_driver_t *led_driver;

#endif // _LED_H_
