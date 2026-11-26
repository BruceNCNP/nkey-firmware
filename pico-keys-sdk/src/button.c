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
#include "button.h"
#include "led/led.h"
#include "pico_time.h"
#if defined(PICO_PLATFORM)
#include "pico/multicore.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/gpio.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#endif
#include "usb.h"
#include "signal.h"

extern void execute_tasks(void);

int (*button_pressed_cb)(uint8_t) = NULL;

static bool req_button_pending = false;
#ifndef ENABLE_EMULATION
static bool async_button_wait = false;
static bool async_button_pressed = false;
static bool async_button_baseline = false;
static bool async_button_hold_ignored = false;
static uint32_t async_button_started = 0;
static uint32_t async_button_timeout = 0;
static volatile bool button_wait_paints = true;
#endif

bool is_req_button_pending(void) {
    return req_button_pending;
}

volatile bool cancel_button = false;
bool touch_accept_button = false;
volatile bool force_button_wait = false;

#if !defined(ENABLE_EMULATION)
#ifdef ESP_PLATFORM
static bool picok_board_button_read(void) {
    int boot_state = gpio_get_level(BOOT_PIN);
    return boot_state == 0;
}
#elif defined(PICO_PLATFORM)
static bool __no_inline_not_in_flash_func(picok_get_bootsel_button)(void) {
    const uint CS_PIN_INDEX = 1;

    // Must disable interrupts, as interrupt handlers may be in flash, and we
    // are about to temporarily disable flash access!
    uint32_t flags = save_and_disable_interrupts();

    // Set chip select to Hi-Z
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    // Note we can't call into any sleep functions in flash right now
    for (volatile int i = 0; i < 1000; ++i);

    // The HI GPIO registers in SIO can observe and control the 6 QSPI pins.
    // Note the button pulls the pin *low* when pressed.
#ifdef PICO_RP2040
    #define CS_BIT (1u << 1)
#else
    #define CS_BIT SIO_GPIO_HI_IN_QSPI_CSN_BITS
#endif
    bool button_state = !(sio_hw->gpio_hi_in & CS_BIT);

    // Need to restore the state of chip select, else we are going to have a
    // bad time when we return to code in flash!
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(flags);

    return button_state;
}
static bool picok_board_button_read(void) {
  return picok_get_bootsel_button();
}
#else
static bool picok_board_button_read(void) {
    return true; // always unpressed
}
#endif
static bool button_pressed_state = false;
static bool button_last_level = false;
static uint32_t button_pressed_time = 0;
static uint8_t button_press = 0;
static bool button_hold_state = false;
static uint32_t button_hold_started = 0;
static uint32_t button_last_poll = 0;
volatile uint32_t button_pressed_duration = 0;

static void button_feedback_barrier(void) {
#if defined(PICO_PLATFORM)
    __dmb();
#elif defined(ESP_PLATFORM)
    __asm__ __volatile__("memw" ::: "memory");
#endif
}

void button_set_wait_feedback(bool paint) {
    button_feedback_barrier();
    button_wait_paints = paint;
    button_feedback_barrier();
}

static bool button_feedback_enabled(void) {
    button_feedback_barrier();
    return button_wait_paints;
}

static bool button_sample(bool *pressed) {
#if defined(PICO_PLATFORM)
    if (!multicore_lockout_start_timeout_us(1000)) {
        return false;
    }
#endif
    *pressed = picok_board_button_read();
#if defined(PICO_PLATFORM)
    multicore_lockout_end_timeout_us(1000);
#endif
    return true;
}

int button_wait_core_event(uint32_t *event) {
    for (;;) {
        queue_remove_blocking(&usb_to_card_q, event);
        if (*event == EV_EXIT) {
            /* The card thread acks EV_EXIT only at the top of its loop.
             * Putting it back lets that loop run after this wait returns. */
            queue_add_blocking(&usb_to_card_q, event);
            return 2;
        }
        if (*event == EV_BUTTON_PRESSED) {
            return 0;
        }
        if (*event == EV_BUTTON_TIMEOUT) {
            return 1;
        }
        if (*event == EV_BUTTON_CANCELLED) {
            return 2;
        }
    }
}

void button_wait_start(void) {
    button_wait_start_timeout(button_timeout_seconds());
}

void button_wait_start_timeout(uint32_t timeout_seconds) {
    uint32_t button_timeout = timeout_seconds * 1000;
    if (button_timeout == 0 && !force_button_wait) {
        signal_emit(SIGNAL_USER_PRESENCE_COMPLETED);
        uint32_t flag = EV_BUTTON_PRESSED;
        queue_try_add(&usb_to_card_q, &flag);
        return;
    }
    if (button_timeout == 0) {
        button_timeout = 30000;
    }
    signal_user_presence_request_data_t data = {
        .timeout = button_timeout / 1000,
    };
    signal_emit_param(SIGNAL_USER_PRESENCE_REQUEST, &data);
    cancel_button = false;
    async_button_wait = true;
    async_button_pressed = false;
    async_button_baseline = false;
    async_button_hold_ignored = false;
    bool held = false;
    if (button_sample(&held)) {
        async_button_baseline = true;
        async_button_hold_ignored = held;
    }
    async_button_started = board_millis();
    async_button_timeout = button_timeout;
    req_button_pending = true;
    if (button_feedback_enabled()) {
        led_authorization_wait();
    }
    else {
        led_idle();
    }
}

void button_wait_poll(bool pressed) {
    if (!async_button_wait) {
        return;
    }
    uint32_t now = board_millis();
    if (!async_button_baseline) {
        async_button_baseline = true;
        async_button_hold_ignored = pressed;
    }
    else if (async_button_hold_ignored) {
        if (!pressed) {
            async_button_hold_ignored = false;
        }
    }
    else if (!async_button_pressed && pressed) {
        async_button_pressed = true;
    }
    button_event_t result = BUTTON_EV_NONE;
    if (cancel_button) {
        result = BUTTON_EV_CANCELLED;
    }
    else if (async_button_started + async_button_timeout < now || (async_button_pressed && async_button_started + 15000 < now)) {
        result = BUTTON_EV_TIMEOUT;
    }
    else if (!async_button_hold_ignored && async_button_pressed && !pressed) {
        result = BUTTON_EV_PRESSED;
    }
    if (result == BUTTON_EV_NONE) {
        return;
    }
    async_button_wait = false;
    req_button_pending = false;
    uint32_t flag = 0;
    bool paint = button_feedback_enabled();
    if (result == BUTTON_EV_PRESSED) {
        if (paint) {
            led_idle();
        }
        flag = EV_BUTTON_PRESSED;
    }
    else if (result == BUTTON_EV_TIMEOUT) {
        if (paint) {
            led_authorization_failure();
        }
        flag = EV_BUTTON_TIMEOUT;
    }
    else if (result == BUTTON_EV_CANCELLED) {
        if (paint) {
            led_authorization_failure();
        }
        flag = EV_BUTTON_CANCELLED;
    }
    queue_try_add(&usb_to_card_q, &flag);
    if (result == BUTTON_EV_PRESSED) {
        signal_emit(SIGNAL_USER_PRESENCE_COMPLETED);
    }
    else if (result == BUTTON_EV_TIMEOUT) {
        signal_emit(SIGNAL_USER_PRESENCE_TIMEOUT);
    }
    else {
        signal_emit(SIGNAL_USER_PRESENCE_CANCELLED);
    }
}

#else
void button_set_wait_feedback(bool paint) {
    (void)paint;
}
int button_wait_core_event(uint32_t *event) {
    (void) event;
    return 0;
}
#endif

uint32_t button_timeout_seconds(void) {
#ifndef ENABLE_EMULATION
    if (phy_data.button_timeout_present) {
        return phy_data.button_timeout_s;
    }
    return PHY_BUTTON_TIMEOUT_S_DEFAULT;
#else
    return 0;
#endif
}

void button_task(void) {
#ifndef ENABLE_EMULATION
    uint32_t now = board_millis();
    if (now > 1000 && now - button_last_poll >= 10 && (async_button_wait || !is_busy())) { // wait 1 second to boot up
        bool current_button_state = false;
        if (!button_sample(&current_button_state)) {
            button_last_poll = now;
            if (async_button_wait) {
                button_wait_poll(button_last_level);
            }
            return;
        }
        button_last_level = current_button_state;
        button_last_poll = now;
        if (async_button_wait) {
            button_wait_poll(current_button_state);
            return;
        }
        if (current_button_state && !button_hold_state) {
            button_hold_started = now;
            button_pressed_duration = 0;
        }
        else if (!current_button_state && button_hold_state) {
            button_pressed_duration = button_hold_started == 0 ? 0 : now - button_hold_started;
            button_hold_started = 0;
        }
        else if (current_button_state && button_hold_state && button_hold_started != 0) {
            button_pressed_duration = now - button_hold_started;
        }
        button_hold_state = current_button_state;
        if (button_pressed_cb) {
            if (current_button_state != button_pressed_state) {
                if (current_button_state == false) { // unpressed
                    if (button_pressed_time == 0 || button_pressed_time + 1000 > now) {
                        button_press++;
                    }
                    button_pressed_time = now;
                }
                button_pressed_state = current_button_state;
            }
            if (button_pressed_time > 0 && button_press > 0 && button_pressed_time + 1000 < now && button_pressed_state == false) {
                if (button_pressed_cb != NULL) {
                    (*button_pressed_cb)(button_press);
                }
                button_pressed_time = button_press = 0;
            }
        }
    }
#endif
}
