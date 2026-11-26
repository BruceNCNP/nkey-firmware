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
#include "nkey_diag.h"
#include "pico_time.h"
#if defined(PICO_PLATFORM)
#include "hardware/sync.h"
#include "pico/time.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#include "esp_rom_sys.h"
#elif defined(ENABLE_EMULATION)
#include "emulation.h"
#endif

#if defined(PICO_PLATFORM)
#define led_memory_barrier() __dmb()
#define led_reset_gap() busy_wait_us(300)
#elif defined(ESP_PLATFORM)
#define led_memory_barrier() __asm__ __volatile__("memw" ::: "memory")
#define led_reset_gap() esp_rom_delay_us(300)
#else
#define led_memory_barrier() do {} while (0)
#define led_reset_gap() do {} while (0)
#endif

led_driver_t *led_driver = NULL;

enum {
    LED_SHOW_IDLE = 0,
    LED_SHOW_FINITE,
    LED_SHOW_WAIT,
    LED_SHOW_STEADY,
    LED_SHOW_STEADY_REINIT
};

#define LED_BLINK_MS 100
#define LED_WAIT_ON_MS 250
#define LED_WAIT_OFF_MS 250

static volatile bool request_pending = false;
static volatile uint8_t request_kind = LED_SHOW_IDLE;
static volatile uint8_t request_color = LED_COLOR_OFF;
static volatile uint8_t request_count = 0;
static volatile uint32_t request_on_ms = 0;
static volatile uint32_t request_off_ms = 0;

static void led_request(uint8_t kind, uint8_t color, uint8_t count, uint32_t on_ms, uint32_t off_ms) {
    request_kind = kind;
    request_color = color;
    request_count = count;
    request_on_ms = on_ms;
    request_off_ms = off_ms;
    led_memory_barrier();
    request_pending = true;
}

void led_idle(void) {
    led_request(LED_SHOW_IDLE, LED_COLOR_OFF, 0, 0, 0);
}

void led_steady(uint8_t color) {
    led_request(LED_SHOW_STEADY, color, 0, 1, 1);
}

void led_steady_reinit(uint8_t color) {
    led_request(LED_SHOW_STEADY_REINIT, color, 0, 1, 1);
}

void led_usb_ready(void) {
    led_request(LED_SHOW_FINITE, LED_COLOR_GREEN, 1, LED_BLINK_MS, LED_BLINK_MS);
}

void led_authorization_wait(void) {
    led_request(LED_SHOW_WAIT, LED_COLOR_BLUE, 0, LED_WAIT_ON_MS, LED_WAIT_OFF_MS);
}

void led_authorization_success(void) {
    led_request(LED_SHOW_FINITE, LED_COLOR_GREEN, 3, LED_BLINK_MS, LED_BLINK_MS);
}

void led_authorization_failure(void) {
    led_request(LED_SHOW_FINITE, LED_COLOR_RED, 3, LED_BLINK_MS, LED_BLINK_MS);
}

static phy_data_t led_hold;
static phy_data_t *led_hw_mut = NULL;
static bool bound_valid = false;
static uint8_t bound_gpio = 0;
static uint8_t bound_driver = 0;

#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
static bool in_diag_mode = false;
static uint8_t show_kind = LED_SHOW_IDLE;
static uint8_t show_color = LED_COLOR_OFF;
static uint8_t show_remaining = 0;
static uint32_t show_on_ms = 0;
static uint32_t show_off_ms = 0;
static bool show_phase_on = false;
static uint32_t show_deadline = 0;
#endif

const struct phy_data *led_hw_config(void) {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    return led_hw_mut != NULL ? led_hw_mut : &phy_data;
#else
    return &led_hold;
#endif
}

static void led_bind_target(phy_data_t *target, bool paint_off);

extern led_driver_t led_driver_pico;
extern led_driver_t led_driver_cyw43;
extern led_driver_t led_driver_ws2812;
extern led_driver_t led_driver_neopixel;
extern led_driver_t led_driver_pimoroni;

static void led_driver_init_dummy(void) {
    // Do nothing
}

static void led_driver_color_dummy(uint8_t color, uint32_t led_brightness, float progress) {
    (void)color;
    (void)led_brightness;
    (void)progress;
    // Do nothing
}

led_driver_t led_driver_dummy = {
    .init = led_driver_init_dummy,
    .set_color = led_driver_color_dummy,
};

bool led_output_unchanged(bool gpio_present, uint8_t gpio, bool driver_present, uint8_t driver) {
    if (!bound_valid || led_driver == NULL || led_driver == &led_driver_dummy) {
        return false;
    }
    if (!gpio_present || !driver_present) {
        return false;
    }
    return bound_gpio == gpio && bound_driver == driver;
}

static void led_bind_target(phy_data_t *target, bool paint_off) {
    led_hw_mut = target;
    led_driver = &led_driver_dummy;
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    // Guess default driver
#if defined(PIMORONI_TINY2040) || defined(PIMORONI_TINY2350)
    led_driver = &led_driver_pimoroni;
    target->led_driver = target->led_driver_present ? target->led_driver : PHY_LED_DRIVER_PIMORONI;
    target->led_gpio = target->led_gpio_present ? target->led_gpio : PICO_DEFAULT_LED_PIN;
#elif defined(CYW43_WL_GPIO_LED_PIN)
    led_driver = &led_driver_cyw43;
    target->led_driver = target->led_driver_present ? target->led_driver : PHY_LED_DRIVER_CYW43;
    target->led_gpio = target->led_gpio_present ? target->led_gpio : CYW43_WL_GPIO_LED_PIN;
#elif defined(PICO_DEFAULT_WS2812_PIN)
    led_driver = &led_driver_ws2812;
    target->led_driver = target->led_driver_present ? target->led_driver : PHY_LED_DRIVER_WS2812;
    target->led_gpio = target->led_gpio_present ? target->led_gpio : PICO_DEFAULT_WS2812_PIN;
#elif defined(ESP_PLATFORM)
    #if defined(CONFIG_IDF_TARGET_ESP32S3)
        #define NEOPIXEL_PIN GPIO_NUM_48
    #elif defined(CONFIG_IDF_TARGET_ESP32S2)
        #define NEOPIXEL_PIN GPIO_NUM_15
    #elif defined(CONFIG_IDF_TARGET_ESP32C6)
        #define NEOPIXEL_PIN GPIO_NUM_8
    #else
        #define NEOPIXEL_PIN GPIO_NUM_27
    #endif
    led_driver = &led_driver_neopixel;
    target->led_driver = target->led_driver_present ? target->led_driver : PHY_LED_DRIVER_NEOPIXEL;
    target->led_gpio = target->led_gpio_present ? target->led_gpio : NEOPIXEL_PIN;
#elif defined(PICO_DEFAULT_LED_PIN)
    led_driver = &led_driver_pico;
    target->led_driver = target->led_driver_present ? target->led_driver : PHY_LED_DRIVER_PICO;
    target->led_gpio = target->led_gpio_present ? target->led_gpio : PICO_DEFAULT_LED_PIN;
#endif
    if (target->led_driver_present) {
        switch (target->led_driver) {
            case PHY_LED_DRIVER_PICO:
                led_driver = &led_driver_pico;
                break;
#ifdef ESP_PLATFORM
            case PHY_LED_DRIVER_NEOPIXEL:
                led_driver = &led_driver_neopixel;
                break;
#else
#ifdef CYW43_WL_GPIO_LED_PIN
            case PHY_LED_DRIVER_CYW43:
                led_driver = &led_driver_cyw43;
                break;
#endif
            case PHY_LED_DRIVER_WS2812:
                led_driver = &led_driver_ws2812;
                break;
            case PHY_LED_DRIVER_PIMORONI:
                led_driver = &led_driver_pimoroni;
                break;
#endif
            default:
                break;
        }
    }
    target->led_driver_present = true;
    target->led_gpio_present = true;
    led_driver->init();
    if (paint_off) {
        led_driver->set_color(LED_COLOR_OFF, 0, 0);
    }
#else
    (void)target;
    (void)paint_off;
#endif
}

#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
static bool led_pin_matches(const phy_data_t *phy) {
    if (!bound_valid || phy == NULL) {
        return false;
    }
    if (!phy->led_gpio_present || !phy->led_driver_present) {
        return false;
    }
    return phy->led_gpio == bound_gpio && phy->led_driver == bound_driver;
}

static void led_remember_binding(const phy_data_t *phy) {
    bound_gpio = phy->led_gpio;
    bound_driver = phy->led_driver;
    bound_valid = true;
}

static void led_paint(uint8_t color, float progress) {
    if (led_driver != NULL) {
        led_driver->set_color(color, MAX_BTNESS, progress);
    }
}

static void led_apply_hold(bool paint_off_on_rebind) {
    if (!led_pin_matches(&led_hold)) {
        led_bind_target(&led_hold, paint_off_on_rebind);
        led_reset_gap();
        led_remember_binding(&led_hold);
    }
    else {
        led_hw_mut = &led_hold;
    }
}

static uint8_t led_diag_color(uint8_t mode) {
    switch (mode) {
        case 1:
            return LED_COLOR_RED;
        case 2:
            return LED_COLOR_GREEN;
        case 3:
            return LED_COLOR_BLUE;
        default:
            return LED_COLOR_CYAN;
    }
}

static void led_begin_show(uint8_t kind, uint8_t color, uint8_t count, uint32_t on_ms, uint32_t off_ms, uint32_t now) {
    show_kind = kind;
    show_color = color;
    show_remaining = count;
    show_on_ms = on_ms;
    show_off_ms = off_ms;
    if (kind == LED_SHOW_STEADY) {
        led_paint(color, 1.0f);
        return;
    }
    if (kind == LED_SHOW_IDLE || on_ms == 0 || off_ms == 0) {
        show_kind = LED_SHOW_IDLE;
        led_paint(LED_COLOR_OFF, 0);
        return;
    }
    show_phase_on = true;
    show_deadline = now + on_ms;
    led_paint(color, 1.0f);
}

static void led_restore_official(void) {
    in_diag_mode = false;
    request_pending = false;
    show_kind = LED_SHOW_IDLE;
    if (!led_pin_matches(&phy_data)) {
        led_bind_target(&phy_data, false);
        led_reset_gap();
        led_remember_binding(&phy_data);
    }
    else {
        led_hw_mut = &phy_data;
    }
    led_paint(LED_COLOR_OFF, 0);
}

static void led_consume_diag(uint32_t now) {
    nkey_diag_request_t request;
    if (!nkey_diag_take(&request)) {
        return;
    }
    if (request.cmd == DIAG_CMD_EXIT) {
        led_restore_official();
        nkey_diag_mark_applied(request.seq);
        return;
    }
    led_hold = request.temp_phy;
    if (request.cmd == DIAG_CMD_TEMP_PHY) {
        led_apply_hold(false);
        in_diag_mode = false;
        request_pending = false;
        show_kind = LED_SHOW_IDLE;
        nkey_diag_mark_applied(request.seq);
        return;
    }
    led_apply_hold(false);
    in_diag_mode = true;
    request_pending = false;
    if (request.cmd == DIAG_CMD_LED_STATIC) {
        led_begin_show(LED_SHOW_STEADY, led_diag_color(request.color_mode), 0, 1, 1, now);
    }
    else if (request.cmd == DIAG_CMD_LED_PATTERN && request.pattern_id == 1) {
        led_begin_show(LED_SHOW_WAIT, LED_COLOR_BLUE, 0, LED_WAIT_ON_MS, LED_WAIT_OFF_MS, now);
    }
    else if (request.cmd == DIAG_CMD_LED_PATTERN && request.pattern_id == 2) {
        led_begin_show(LED_SHOW_FINITE, LED_COLOR_GREEN, 3, LED_BLINK_MS, LED_BLINK_MS, now);
    }
    else if (request.cmd == DIAG_CMD_LED_PATTERN && request.pattern_id == 3) {
        led_begin_show(LED_SHOW_FINITE, LED_COLOR_RED, 3, LED_BLINK_MS, LED_BLINK_MS, now);
    }
    nkey_diag_mark_applied(request.seq);
}

static void led_accept_request(uint32_t now) {
    led_memory_barrier();
    show_kind = request_kind;
    show_color = request_color;
    show_remaining = request_count;
    show_on_ms = request_on_ms;
    show_off_ms = request_off_ms;
    request_pending = false;
    if (show_kind == LED_SHOW_STEADY_REINIT) {
        phy_data_t *target = led_hw_mut != NULL ? led_hw_mut : &phy_data;
        led_bind_target(target, false);
        led_reset_gap();
        led_remember_binding(target);
        led_paint(show_color, 1.0f);
        show_kind = LED_SHOW_STEADY;
        return;
    }
    led_begin_show(show_kind, show_color, show_remaining, show_on_ms, show_off_ms, now);
}
#endif

void led_blinking_task(void) {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    uint32_t now = board_millis();
    led_consume_diag(now);
    if (led_driver == NULL) {
        return;
    }
    if (request_pending) {
        if (in_diag_mode) {
            request_pending = false;
        }
        else {
            led_accept_request(now);
            return;
        }
    }
    if (show_kind == LED_SHOW_IDLE || show_kind == LED_SHOW_STEADY || now < show_deadline) {
        return;
    }
    if (show_phase_on) {
        show_phase_on = false;
        show_deadline = now + show_off_ms;
        led_paint(LED_COLOR_OFF, 0);
        return;
    }
    if (show_kind == LED_SHOW_FINITE) {
        if (show_remaining > 0) {
            show_remaining--;
        }
        if (show_remaining == 0) {
            show_kind = LED_SHOW_IDLE;
            return;
        }
    }
    show_phase_on = true;
    show_deadline = now + show_on_ms;
    led_paint(show_color, 1.0f);
#endif
}

void led_init(void) {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    led_bind_target(&phy_data, true);
    led_remember_binding(&phy_data);
#else
    led_driver = &led_driver_dummy;
#endif
}
