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
// File:    damper.c
// Desc:    Implements the vent damper state machine that sequences the
//          SG90 actuator and fails open on loss of authority.
// Created: 2026

#include "pico/time.h"
#include "damper.h"
#include "servo.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Current damper position and health state.
 */
static damper_state_t g_damper_state;

/**
 * @brief Pending travel target, true when the vent is opening.
 */
static bool g_damper_target_open;

/**
 * @brief Absolute time in microseconds when the pending travel completes.
 */
static uint64_t g_damper_move_until_us;

/**
 * @brief Complete a pending travel by driving the damper actuator.
 *
 * @param void No parameters.
 * @return void
 */
static void damper_complete(void) {
    if (g_damper_target_open) {
        vent_open();
        g_damper_state = DAMPER_STATE_OPEN;
        return;
    }
    vent_close();
    g_damper_state = DAMPER_STATE_CLOSED;
}

void damper_init(void) {
    g_damper_target_open = true;
    g_damper_state = DAMPER_STATE_OPEN;
    vent_open();
}

damper_state_t damper_state(void) {
    return g_damper_state;
}

bool damper_is_open(void) {
    return g_damper_state == DAMPER_STATE_OPEN;
}

void damper_apply_command(bool open, bool authorized) {
    if (!authorized) {
        return;
    }
    g_damper_target_open = open;
    g_damper_state = DAMPER_STATE_MOVING;
    g_damper_move_until_us =
        time_us_64() + (uint64_t)DAMPER_TRAVEL_MS * 1000u;
}

void damper_tick(void) {
    if (g_damper_state != DAMPER_STATE_MOVING) {
        return;
    }
    if (time_us_64() < g_damper_move_until_us) {
        return;
    }
    damper_complete();
}

void damper_fail_safe(void) {
    vent_open();
    g_damper_target_open = true;
    g_damper_state = DAMPER_STATE_FAULT;
}
