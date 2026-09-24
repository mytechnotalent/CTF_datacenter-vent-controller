// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/datacenter-vent-controller
// File:    monitor.c
// Desc:    Implements the vent controller state machine that ties the
//          local maintenance remote, the sealed vent command path, the
//          rack temperature sensor, the vent damper, and the RYLR998
//          vault control link together. The production build never
//          applies an untrusted frame and never executes a remotely
//          issued task: the SANDBOX_ONLY locker is the only covert path
//          and it is compiled out of the clean build.
// Created: 2026

#include "vent.h"
#include "monitor.h"
#include "sensor.h"
#include "display.h"
#include "radio.h"
#include "status_led.h"
#include "button.h"
#include "servo.h"
#include "ir_remote.h"
#include "damper.h"
#include "control.h"
#include "implant.h"
#include "crypto_aead.h"
#include "crypto_kdf.h"
#include "field_secrets.h"
#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "pico/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Guarded vent states derived from authorized vent commands.
 */
typedef enum vent_state {
    /**
     * @brief Hall is cooling and the damper is open.
     */
    VENT_STATE_COOLING = 0,
    /**
     * @brief A manual purge is pending authorization.
     */
    VENT_STATE_PURGE_PENDING = 1,
    /**
     * @brief The hall is hot and the damper is closed.
     */
    VENT_STATE_HALL_HOT = 2,
    /**
     * @brief The control link was lost or a command was rejected.
     */
    VENT_STATE_DENIED = 3,
} vent_state_t;

/**
 * @brief Module-ready flag.
 */
static bool g_ready;

/**
 * @brief Initialized I2C peripheral handle for the LCD backpack.
 */
static i2c_inst_t *g_i2c;

/**
 * @brief Initialized I2C backpack address for the LCD.
 */
static uint8_t g_i2c_addr;

/**
 * @brief Derived XChaCha20-Poly1305 field key for the control link.
 */
static uint8_t g_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been derived and installed.
 */
static bool g_key_ready;

/**
 * @brief True once a sealed vent command has been accepted.
 */
static bool g_link_seen;

/**
 * @brief Absolute time in microseconds of the last accepted command.
 */
static uint64_t g_last_rx_us;

/**
 * @brief Last observed rack temperature in-range verdict.
 */
static bool g_temp_ok;

/**
 * @brief Last observed rack temperature in tenths of a degree Celsius.
 */
static int16_t g_temp_tenths;

/**
 * @brief Guarded vent state.
 */
static vent_state_t g_state;

/**
 * @brief Rack zone recovered from the last accepted command.
 */
static int16_t g_zone;

/**
 * @brief True while a manual purge awaits authorization.
 */
static bool g_purge_pending;

/**
 * @brief Last locker state applied to the damper and display.
 */
static bool g_lock_shown;

/**
 * @brief First LCD vault render line buffer.
 */
static char g_line1[DISPLAY_LINE_LEN];

/**
 * @brief Second LCD vault render line buffer.
 */
static char g_line2[DISPLAY_LINE_LEN];

/**
 * @brief Inbound radio line accumulator.
 */
static char g_rx_line[RADIO_LINE_BUF_LEN];

/**
 * @brief Number of bytes currently held in the inbound line accumulator.
 */
static size_t g_rx_len;

/**
 * @brief Monotonic reading-cycle counter for the interactive console.
 */
static uint32_t g_cycles;

/**
 * @brief Probe one I2C address and report whether it acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to probe.
 * @param addr The 7-bit address to probe.
 * @return bool true when the address acknowledged.
 */
static bool i2c_probe(i2c_inst_t *i2c, uint8_t addr) {
    uint8_t dummy = 0u;
    if (i2c_write_blocking(i2c, addr, &dummy, 1u, false) < 0) {
        return false;
    }
    printf("  found 0x%02X\n", (unsigned)addr);
    return true;
}

/**
 * @brief Probe the I2C bus and print every device that acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to scan.
 * @return void
 */
static void i2c_bus_scan(i2c_inst_t *i2c) {
    uint8_t addr;
    uint8_t found = 0u;
    printf("I2C scan:\n");
    for (addr = 0x08u; addr < 0x78u; ++addr) {
        found += i2c_probe(i2c, addr) ? 1u : 0u;
    }
    if (found == 0u) {
        printf("  no devices\n");
    }
}

/**
 * @brief Initialize the I2C bus pins and scan the bus.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_bus_init(void) {
    i2c_init(VENT_I2C, VENT_I2C_BAUD);
    gpio_set_function(VENT_I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(VENT_I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(VENT_I2C_SDA);
    gpio_pull_up(VENT_I2C_SCL);
    i2c_bus_scan(VENT_I2C);
}

/**
 * @brief Configure the onboard heartbeat LED.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_gpio_init(void) {
    gpio_init(VENT_LED_PIN);
    gpio_set_dir(VENT_LED_PIN, GPIO_OUT);
    gpio_put(VENT_LED_PIN, 0);
}

/**
 * @brief Pulse the onboard heartbeat LED once.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_heartbeat(void) {
    gpio_put(VENT_LED_PIN, 1);
    sleep_us(MONITOR_HEARTBEAT_US);
    gpio_put(VENT_LED_PIN, 0);
}

/**
 * @brief Clear every latched vent state flag.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_reset_state(void) {
    g_link_seen = false;
    g_last_rx_us = 0u;
    g_temp_ok = false;
    g_temp_tenths = 0;
    g_state = VENT_STATE_COOLING;
    g_zone = 0;
    g_purge_pending = false;
    g_lock_shown = false;
}

/**
 * @brief Compute the damper target, honoring the SANDBOX_ONLY lock.
 *
 * @param void No parameters.
 * @return bool true when the vent should be open.
 */
static bool monitor_open_target(void) {
#ifdef SANDBOX_ONLY
    if (implant_lock_active()) {
        return false;
    }
#endif
    return g_state != VENT_STATE_HALL_HOT;
}

/**
 * @brief Drive the vent damper for the current guarded vent state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_apply_state(void) {
    damper_apply_command(monitor_open_target(), true);
}

/**
 * @brief Initialize the LED, LCD handles, damper, and vent state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init(void) {
    monitor_gpio_init();
    g_i2c = VENT_I2C;
    g_i2c_addr = VENT_LCD_ADDR;
    monitor_reset_state();
    damper_init();
    monitor_apply_state();
    g_ready = true;
}

/**
 * @brief Initialize the human interface and actuator peripherals.
 *
 * @param void No parameters.
 * @return bool true when the LEDs, button, servo, and infrared eye ready.
 */
static bool monitor_peripherals_init(void) {
    return status_led_init() && purge_init() && servo_init() &&
           ir_remote_init();
}

/**
 * @brief Initialize the SANDBOX_ONLY locker when it is compiled in.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_implant_init(void) {
#ifdef SANDBOX_ONLY
    implant_init();
#endif
}

/**
 * @brief Re-apply the damper when the SANDBOX_ONLY lock state changes.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_sync_lock(void) {
#ifdef SANDBOX_ONLY
    bool locked = implant_lock_active();
    if (locked == g_lock_shown) {
        return;
    }
    g_lock_shown = locked;
    monitor_apply_state();
#endif
}

/**
 * @brief Derive the field key from the committed lab secret.
 *
 * LAB-ONLY: production must provision the field key through OTP rather
 * than deriving it from a committed passphrase and salt.
 *
 * @param void No parameters.
 * @return bool true when the field key was derived and installed.
 */
static bool monitor_derive_key(void) {
    bool ok = crypto_kdf_argon2id((const uint8_t *)FIELD_SECRET_PASSPHRASE,
                                  strlen(FIELD_SECRET_PASSPHRASE),
                                  FIELD_SECRET_SALT, 16u, g_key);
    g_key_ready = ok;
    control_set_key(ok ? g_key : NULL);
    return ok;
}

/**
 * @brief Print the boot banner and the interactive console control hint.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_banner(void) {
    printf("=== OPERATION IRON VAULT // ACT VIII DATACENTER VENT ===\n");
    printf("Remote: CH+ 0x47 PURGE, CH- 0x45 TEST, CH 0x46 ACK\n");
    printf("Button: manual purge request, never bypasses authorization\n");
}

/**
 * @brief Bring up the vent state and command path.
 *
 * @param void No parameters.
 * @return bool true when the field key was installed.
 */
static bool monitor_start(void) {
    monitor_state_init();
    control_init();
    monitor_implant_init();
    monitor_sync_lock();
    monitor_banner();
    return monitor_derive_key();
}

bool monitor_init(void) {
    monitor_bus_init();
    if (!monitor_peripherals_init() || !sensor_init() ||
        !radio_init(VENT_UART) ||
        !display_init(VENT_I2C, VENT_LCD_ADDR)) {
        printf("INIT FAIL\n");
        return false;
    }
    return monitor_start();
}

void monitor_deinit(void) {
    g_ready = false;
    control_deinit();
}

void monitor_purge_request(void) {
    g_purge_pending = false;
}

/**
 * @brief Map an authorized command byte to the guarded vent state.
 *
 * @param command Guarded vent command code.
 * @return vent_state_t Guarded vent state for the command.
 */
static vent_state_t monitor_state_for(uint8_t command) {
    if (command == VENT_COMMAND_OPEN) return VENT_STATE_COOLING;
    if (command == VENT_COMMAND_CLOSE) return VENT_STATE_HALL_HOT;
    if (command == VENT_COMMAND_PURGE) return VENT_STATE_PURGE_PENDING;
    return VENT_STATE_DENIED;
}

/**
 * @brief Map a guarded vent state to its tower light lamp.
 *
 * @param state Guarded vent state to map.
 * @return vent_led_state_t Tower light state for the vent state.
 */
static vent_led_state_t monitor_led_for(vent_state_t state) {
#ifdef SANDBOX_ONLY
    if (implant_lock_active()) return VENT_LOCKED;
#endif
    if (state == VENT_STATE_DENIED) return VENT_HALL_HOT;
    if (state == VENT_STATE_HALL_HOT) return VENT_HALL_HOT;
    if (state == VENT_STATE_PURGE_PENDING) return VENT_LOCKED;
    if (g_purge_pending) return VENT_LOCKED;
    return VENT_COOLING_OK;
}

/**
 * @brief Render a guarded vent state as a short status label.
 *
 * @param state Guarded vent state to render.
 * @return const char* NUL-terminated state label.
 */
static const char *monitor_state_text(vent_state_t state) {
#ifdef SANDBOX_ONLY
    if (implant_mask_active()) return "MAINT";
#endif
    if (state == VENT_STATE_COOLING) return "COOL";
    if (state == VENT_STATE_PURGE_PENDING) return "PURGE";
    if (state == VENT_STATE_HALL_HOT) return "HOT";
    return "FAIL";
}

/**
 * @brief Render the control link status as a short label.
 *
 * @param void No parameters.
 * @return const char* NUL-terminated link label.
 */
static const char *monitor_link_text(void) {
    return g_link_seen ? "UP" : "--";
}

/**
 * @brief Render the locker marker as a short label.
 *
 * @param void No parameters.
 * @return const char* NUL-terminated locker label.
 */
static const char *monitor_lock_text(void) {
#ifdef SANDBOX_ONLY
    return implant_marker_set() ? "LOCK" : "--";
#else
    return "--";
#endif
}

/**
 * @brief Format the active rack zone as a short decimal text.
 *
 * @param out Pointer to the mutable text buffer.
 * @param out_len Capacity of the text buffer in bytes.
 * @return void
 */
static void monitor_zone_text(char *out, size_t out_len) {
    snprintf(out, out_len, "%d", (int)g_zone);
}

/**
 * @brief Format the rack temperature as a short decimal text.
 *
 * @param out Pointer to the mutable text buffer.
 * @param out_len Capacity of the text buffer in bytes.
 * @return void
 */
static void monitor_temp_text(char *out, size_t out_len) {
    snprintf(out, out_len, "%d", (int)g_temp_tenths);
}

/**
 * @brief Format the vault status and zone lines into the render buffers.
 *
 * @param zone Pointer to the formatted zone text.
 * @param temp Pointer to the formatted temperature text.
 * @return void
 */
static void monitor_format_lines(const char *zone, const char *temp) {
    snprintf(g_line1, DISPLAY_LINE_LEN, "ST:%-5s L:%s",
             monitor_state_text(g_state), monitor_link_text());
    snprintf(g_line2, DISPLAY_LINE_LEN, "Z:%s T:%s K:%s",
             zone, temp, monitor_lock_text());
}

/**
 * @brief Render the vault status and zone lines to the 1602 LCD.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_render(void) {
    char zone[8];
    char temp[8];
    monitor_zone_text(zone, sizeof(zone));
    monitor_temp_text(temp, sizeof(temp));
    monitor_format_lines(zone, temp);
    display_render_lines(g_i2c, g_i2c_addr, g_line1, g_line2);
}

/**
 * @brief Sample the DHT11 rack sensor and classify it.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_refresh_temp(void) {
    dht_reading_t reading;
    g_cycles += 1u;
    if (sensor_read(&reading) != SENSOR_RESULT_OK) {
        printf("RACK read failed -> WARNING\n");
        g_temp_ok = false;
        return;
    }
    g_temp_ok = rack_temp_ok(&reading);
    g_temp_tenths = reading.temperature_tenths;
}

/**
 * @brief Consume one debounced manual purge press and raise the request.
 *
 * A manual purge raises the purge pending indication. It never changes
 * the guarded state on its own, so it cannot silently bypass
 * authorization.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_purge(void) {
    if (!purge_consume_press()) {
        return;
    }
    g_purge_pending = true;
    printf("BUTTON purge request -> pending\n");
}

/**
 * @brief Map a decoded maintenance remote command to its name.
 *
 * @param command Decoded NEC command byte.
 * @return const char* Command name string.
 */
static const char *monitor_ir_name(uint8_t command) {
    if (command == VENT_IR_PURGE) return "PURGE";
    if (command == VENT_IR_TEST) return "TEST";
    if (command == VENT_IR_ACK) return "ACK";
    return "UNKNOWN";
}

/**
 * @brief Apply one decoded infrared maintenance remote command.
 *
 * @param cmd Pointer to the decoded infrared command.
 * @return void
 */
static void monitor_apply_ir_command(const ir_command_t *cmd) {
    printf("IR %s (0x%02X)\n", monitor_ir_name(cmd->command), (unsigned)cmd->command);
    if (cmd->command == VENT_IR_TEST) {
        return;
    }
    if (cmd->command == VENT_IR_PURGE || cmd->command == VENT_IR_ACK) {
        g_purge_pending = true;
    }
}

/**
 * @brief Poll the infrared maintenance remote for a command.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_ir(void) {
    ir_command_t cmd;
    if (!ir_remote_poll(&cmd)) {
        return;
    }
    monitor_apply_ir_command(&cmd);
}

/**
 * @brief Apply one authorized command to the damper and vent state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_apply_command(void) {
    g_state = monitor_state_for(control_command());
    g_zone = (int16_t)control_zone();
    g_purge_pending = false;
    monitor_apply_state();
}

/**
 * @brief Verify and apply one inbound vent frame.
 *
 * The sealed open, close, or purge command is authenticated and
 * authorized before it can move the damper. No manual purge can bypass
 * this authorization, and no untrusted task is ever executed.
 *
 * @param hex Pointer to the inbound frame text.
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_apply_frame(const char *hex, uint64_t now_us) {
    if (!control_handle_frame(hex)) {
        return;
    }
    g_link_seen = true;
    g_last_rx_us = now_us;
    monitor_apply_command();
}

/**
 * @brief Fail open to the cooling posture on a silent control link.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_fail_open(void) {
    g_state = VENT_STATE_DENIED;
    g_zone = 0;
    g_purge_pending = false;
    damper_fail_safe();
}

/**
 * @brief Drain inbound radio lines and apply any sealed command.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_rx_tick(uint64_t now_us) {
    radio_rcv_t rcv;
    while (radio_line_pump(VENT_UART, g_rx_line, &g_rx_len)) {
        if (radio_parse_rcv(g_rx_line, &rcv) == RADIO_RESULT_OK) {
            printf("RX from 0x%04X, %u bytes\n", (unsigned)rcv.sender, (unsigned)rcv.len);
            monitor_apply_frame(rcv.payload, now_us);
        }
    }
}

/**
 * @brief Drive to the fail-open posture when the control link goes silent.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_check_link(uint64_t now_us) {
    if (!g_link_seen) {
        return;
    }
    if ((now_us - g_last_rx_us) <= (uint64_t)VENT_LINK_WAIT_MS * 1000u) {
        return;
    }
    monitor_fail_open();
}

/**
 * @brief Service the purge button, maintenance remote, and control link.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_service_inputs(uint64_t now_us) {
    monitor_handle_purge();
    monitor_handle_ir();
    monitor_rx_tick(now_us);
    monitor_check_link(now_us);
}

/**
 * @brief Advance the SANDBOX_ONLY locker when it is compiled in.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_implant_tick(void) {
#ifdef SANDBOX_ONLY
    implant_tick();
#endif
}

/**
 * @brief Drive exactly one tower light lamp for the current vent state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_drive_leds(void) {
    status_led_show(monitor_led_for(g_state));
}

/**
 * @brief Print one live rack status line for the interactive console.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_log_reading(void) {
    printf("RACK t=%d ok=%d LED=%d cyc=%u\n", (int)g_temp_tenths, (int)g_temp_ok, (int)monitor_led_for(g_state), (unsigned)g_cycles);
}

/**
 * @brief Drive the tower light, damper, locker, and vault display.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_service_outputs(void) {
    monitor_implant_tick();
    monitor_sync_lock();
    damper_tick();
    monitor_drive_leds();
    monitor_heartbeat();
    monitor_render();
    monitor_log_reading();
}

bool monitor_step(void) {
    uint64_t now_us;
    if (!g_ready) {
        return false;
    }
    now_us = time_us_64();
    monitor_refresh_temp();
    monitor_service_inputs(now_us);
    monitor_service_outputs();
    return true;
}
