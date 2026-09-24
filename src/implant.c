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
// File:    implant.c
// Desc:    Implements the SANDBOX_ONLY FROSTLINE ransom locker: the vent
//          lock, the magic release token, the reserved-sector lock
//          marker, and the CoreDebug anti-debug trap. Compiled only
//          under SANDBOX_ONLY.
// Created: 2026

#include "implant.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef SANDBOX_ONLY

#ifdef IMPLANT_HOST_MOCK
#include "implant_host.h"
/**
 * @brief Read the controllable mock CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (g_mock_implant_dhcsr)
/**
 * @brief Read the mock reserved-sector lock marker.
 */
#define IMPLANT_FLASH_READ() (g_mock_implant_flash)
/**
 * @brief Store the lock marker in the mock reserved sector.
 */
#define IMPLANT_FLASH_WRITE(value) (g_mock_implant_flash = (value))
#else
#include "hardware/flash.h"
#include "hardware/sync.h"
/**
 * @brief Read the real CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (*(volatile uint32_t *)VENT_IMPLANT_DHCSR_ADDR)
/**
 * @brief Read the real reserved-sector lock marker.
 */
#define IMPLANT_FLASH_READ() (*(volatile uint8_t *)VENT_IMPLANT_RESERVE_ADDR)
/**
 * @brief Erase and program the reserved-sector lock marker.
 *
 * @param value Marker byte to store in the reserved sector.
 * @return void
 */
static void implant_flash_write(uint8_t value) {
    uint8_t page[FLASH_PAGE_SIZE];
    uint32_t ints = save_and_disable_interrupts();
    memset(page, 0xFF, sizeof(page));
    page[0] = value;
    flash_range_erase(VENT_IMPLANT_RESERVE_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(VENT_IMPLANT_RESERVE_OFFSET, page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);
}
/**
 * @brief Write the lock marker into the reserved flash sector.
 */
#define IMPLANT_FLASH_WRITE(value) implant_flash_write(value)
#endif

/**
 * @brief Monotonic locker tick counter.
 */
static uint32_t g_implant_ticks;

/**
 * @brief True when the locker is armed to re-assert the lock.
 */
static bool g_implant_active;

/**
 * @brief True while the ransom lock is currently active.
 */
static bool g_implant_locked;

/**
 * @brief Number of lock operations performed this boot.
 */
static size_t g_implant_lock_count;

/**
 * @brief Runtime gate for the ransom vent lock.
 *
 * The corrected build leaves this gate clear, so the locker never closes
 * the vent.
 */
static volatile bool g_implant_lock_gate;

/**
 * @brief Runtime gate for the maintenance LCD mask.
 *
 * The corrected build leaves this gate clear, so the true vent state is
 * never masked.
 */
static volatile bool g_implant_mask_gate;

/**
 * @brief Runtime gate for the reserved-sector lock marker write.
 *
 * The corrected build leaves this gate clear, so no lock marker is
 * programmed.
 */
static volatile bool g_implant_marker_gate;

bool implant_debug_attached(void) {
    return (IMPLANT_DHCSR_READ &
            (VENT_IMPLANT_DHCSR_DEBUGEN | VENT_IMPLANT_DHCSR_HALT)) != 0u;
}

bool implant_marker_set(void) {
    return IMPLANT_FLASH_READ() == (uint32_t)VENT_IMPLANT_LOCK_MARKER;
}

bool implant_lock_active(void) {
    return g_implant_locked;
}

bool implant_mask_active(void) {
    if (!g_implant_mask_gate) {
        return false;
    }
    return g_implant_locked;
}

size_t implant_lock_count(void) {
    return g_implant_lock_count;
}

/**
 * @brief Write the lock marker into the reserved flash sector.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_infect(void) {
    if (!g_implant_marker_gate) {
        return;
    }
    if (implant_marker_set()) {
        return;
    }
    IMPLANT_FLASH_WRITE((uint32_t)VENT_IMPLANT_LOCK_MARKER);
}

/**
 * @brief Report whether the current token matches the release magic.
 *
 * @param token Pointer to the candidate release token bytes.
 * @param len Number of candidate token bytes.
 * @return bool true when the token matches the magic exactly.
 */
static bool implant_token_ok(const uint8_t *token, size_t len) {
    if (token == NULL || len != VENT_IMPLANT_RELEASE_MAGIC_LEN) {
        return false;
    }
    return memcmp(token, VENT_IMPLANT_RELEASE_MAGIC, len) == 0;
}

/**
 * @brief Report whether the autonomous lock interval has elapsed.
 *
 * @param void No parameters.
 * @return bool true when the tick counter hits the lock interval.
 */
static bool implant_tick_due(void) {
    return (g_implant_ticks % VENT_IMPLANT_TICK_INTERVAL) == 0u;
}

/**
 * @brief Reset every locker runtime flag and counter.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_reset_state(void) {
    g_implant_ticks = 0u;
    g_implant_active = false;
    g_implant_locked = false;
    g_implant_lock_count = 0u;
}

void implant_init(void) {
    implant_reset_state();
    if (!g_implant_lock_gate) {
        return;
    }
    if (implant_debug_attached()) {
        return;
    }
    g_implant_active = true;
    g_implant_locked = true;
    implant_infect();
}

void implant_lock(void) {
    if (!g_implant_lock_gate) {
        return;
    }
    if (implant_debug_attached()) {
        return;
    }
    g_implant_active = true;
    g_implant_locked = true;
    implant_infect();
    g_implant_lock_count += 1u;
}

bool implant_release(const uint8_t *token, size_t len) {
    if (implant_debug_attached() || !implant_token_ok(token, len)) {
        return false;
    }
    g_implant_locked = false;
    g_implant_active = false;
    IMPLANT_FLASH_WRITE(0u);
    return true;
}

void implant_neutralize(void) {
    g_implant_locked = false;
    g_implant_active = false;
    IMPLANT_FLASH_WRITE(0u);
}

void implant_tick(void) {
    g_implant_ticks += 1u;
    if (implant_debug_attached()) {
        g_implant_locked = false;
        return;
    }
    if (!g_implant_active || !implant_tick_due()) {
        return;
    }
    g_implant_locked = true;
    implant_infect();
}

#endif // SANDBOX_ONLY
