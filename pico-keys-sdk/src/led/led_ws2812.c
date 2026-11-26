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
#include "led/led.h"

#ifdef PICO_PLATFORM
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "hardware/gpio.h"
#include "pico/time.h"

#define ws2812_wrap_target 0
#define ws2812_wrap 3
#define ws2812_pio_version 0

#define ws2812_T1 3
#define ws2812_T2 3
#define ws2812_T3 4

static const uint16_t ws2812_program_instructions[] = {
            //     .wrap_target
    0x6321, //  0: out    x, 1            side 0 [3]
    0x1223, //  1: jmp    !x, 3           side 1 [2]
    0x1200, //  2: jmp    0               side 1 [2]
    0xa242, //  3: nop                    side 0 [2]
            //     .wrap
};

static const struct pio_program ws2812_program = {
    .instructions = ws2812_program_instructions,
    .length = 4,
    .origin = -1,
    .pio_version = ws2812_pio_version,
#if PICO_PIO_VERSION > 0
    .used_gpio_ranges = 0x0
#endif
};

static inline pio_sm_config ws2812_program_get_default_config(uint offset) {
    pio_sm_config c = pio_get_default_sm_config();
    sm_config_set_wrap(&c, offset + ws2812_wrap_target, offset + ws2812_wrap);
    sm_config_set_sideset(&c, 1, false, false);
    return c;
}

static inline void ws2812_program_init(PIO pio, uint sm, uint offset, uint pin, float freq, bool rgbw) {
    pio_gpio_init(pio, pin);
    pio_sm_set_consecutive_pindirs(pio, sm, pin, 1, true);
    pio_sm_config c = ws2812_program_get_default_config(offset);
    sm_config_set_sideset_pins(&c, pin);
    sm_config_set_out_shift(&c, false, true, rgbw ? 32 : 24);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);
    int cycles_per_bit = ws2812_T1 + ws2812_T2 + ws2812_T3;
    float div = clock_get_hz(clk_sys) / (freq * cycles_per_bit);
    sm_config_set_clkdiv(&c, div);
    pio_sm_init(pio, sm, offset, &c);
    pio_sm_set_enabled(pio, sm, true);
}

static bool ws2812_program_loaded = false;
static uint ws2812_offset = 0;
static uint8_t ws2812_gpio = 0;
static bool ws2812_gpio_ready = false;
static uint32_t ws2812_last_frame_us = 0;

static void led_driver_init_ws2812(void) {
    PIO pio = pio0;
    uint sm = 0;
    if (!ws2812_program_loaded) {
        ws2812_offset = pio_add_program(pio, &ws2812_program);
        ws2812_program_loaded = true;
    } else {
        pio_sm_set_enabled(pio, sm, false);
        if (ws2812_gpio_ready) {
            gpio_deinit(ws2812_gpio);
            ws2812_gpio_ready = false;
        }
    }
    uint8_t gpio = 0;
#ifdef PICO_DEFAULT_WS2812_PIN
    gpio = PICO_DEFAULT_WS2812_PIN;
#endif
    const phy_data_t *hw = led_hw_config();
    if (hw->led_gpio_present) {
        gpio = hw->led_gpio;
    }
    ws2812_program_init(pio, sm, ws2812_offset, gpio, 800000, false);
    ws2812_gpio = gpio;
    ws2812_gpio_ready = true;
    ws2812_last_frame_us = time_us_32();
}

struct urgb_color {
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

static struct urgb_color urgb_color_table[] = {
    {0x00, 0x00, 0x00}, // 0: off       LED_COLOR_OFF
    {0xff, 0x00, 0x00}, // 1: red       LED_COLOR_RED
    {0x00, 0xff, 0x00}, // 2: green     LED_COLOR_GREEN
    {0x00, 0x00, 0xff}, // 3: blue      LED_COLOR_BLUE
    {0xff, 0xff, 0x00}, // 4: yellow    LED_COLOR_YELLOW
    {0xff, 0x00, 0xff}, // 5: magenta   LED_COLOR_MAGENTA
    {0x00, 0xff, 0xff}, // 6: cyan      LED_COLOR_CYAN
    {0xff, 0xff, 0xff}  // 7: white     LED_COLOR_WHITE
};

static inline uint32_t urgb_ordered_u32(uint8_t first, uint8_t second, uint8_t third) {
    return ((uint32_t)first << 16) | ((uint32_t)second << 8) | third;
}

static uint8_t ws2812_channel_order(void) {
    const phy_data_t *hw = led_hw_config();
    if (hw->led_order_present && hw->led_order == PHY_LED_ORDER_RGB) {
        return PHY_LED_ORDER_RGB;
    }
    return PHY_LED_ORDER_GRB;
}

static inline uint32_t urgb_u32(uint8_t r, uint8_t g, uint8_t b) {
    if (ws2812_channel_order() == PHY_LED_ORDER_RGB) {
        return urgb_ordered_u32(r, g, b);
    }
    return urgb_ordered_u32(g, r, b);
}

static inline void ws2812_put_pixel(uint32_t u32_pixel) {
    if (pio_sm_is_tx_fifo_full(pio0, 0)) {
        return;
    }
    uint32_t now = time_us_32();
    uint32_t elapsed = now - ws2812_last_frame_us;
    if (ws2812_last_frame_us != 0 && elapsed < 300) {
        busy_wait_us(300 - elapsed);
        if (pio_sm_is_tx_fifo_full(pio0, 0)) {
            return;
        }
    }
    pio_sm_put(pio0, 0, u32_pixel << 8u);
    ws2812_last_frame_us = time_us_32();
}

static void led_driver_color_ws2812(uint8_t color, uint32_t led_brightness, float progress) {
    const phy_data_t *hw = led_hw_config();
    if (!(hw->opts & PHY_OPT_DIMM)) {
        progress = progress >= 0.5 ? 1 : 0;
    }
    uint32_t led_phy_btness = hw->led_brightness_present ? hw->led_brightness : PHY_LED_MAX_BRIGHTNESS_DEFAULT;

    float brightness = ((float)led_brightness / MAX_BTNESS) * ((float)led_phy_btness / 255.0f) * progress;
    struct urgb_color pixel_color = urgb_color_table[color];
    pixel_color.r = (uint8_t)(pixel_color.r * brightness);
    pixel_color.g = (uint8_t)(pixel_color.g * brightness);
    pixel_color.b = (uint8_t)(pixel_color.b * brightness);

    ws2812_put_pixel(urgb_u32(pixel_color.r, pixel_color.g, pixel_color.b));
}

led_driver_t led_driver_ws2812 = {
    .init = led_driver_init_ws2812,
    .set_color = led_driver_color_ws2812,
};

#endif
