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
// File:    damper.h
// Desc:    Declares the vent damper state machine that sequences the
//          SG90 actuator and fails open on loss of authority.
// Created: 2026

#ifndef DAMPER_H
#define DAMPER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Bounded vent damper travel time in milliseconds.
 */
#define DAMPER_TRAVEL_MS 1000u

/**
 * @brief Vent damper position and health states.
 */
typedef enum damper_state {
    /**
     * @brief Damper is closed, sealing the server hall.
     */
    DAMPER_STATE_CLOSED = 0,
    /**
     * @brief Damper is open for cooling.
     */
    DAMPER_STATE_OPEN = 1,
    /**
     * @brief Damper has failed safe into the open posture.
     */
    DAMPER_STATE_FAULT = 2,
    /**
     * @brief Damper actuator is travelling between positions.
     */
    DAMPER_STATE_MOVING = 3,
} damper_state_t;

/**
 * @brief Initialize the damper state machine and open the vent.
 *
 * @param void No parameters.
 * @return void
 */
void damper_init(void);

/**
 * @brief Return the current damper state.
 *
 * @param void No parameters.
 * @return damper_state_t Current damper state.
 */
damper_state_t damper_state(void);

/**
 * @brief Report whether the vent is currently fully open.
 *
 * @param void No parameters.
 * @return bool true when the vent is open.
 */
bool damper_is_open(void);

/**
 * @brief Apply an authorized open or close command to the vent.
 *
 * Unauthorized commands are refused. An authorized command starts a
 * bounded travel interval that damper_tick completes. This is the
 * guarded command path that prevents an unauthenticated local purge from
 * moving the vent.
 *
 * @param open True to drive the vent open, false to close it.
 * @param authorized True when the caller has validated the command.
 * @return void
 */
void damper_apply_command(bool open, bool authorized);

/**
 * @brief Advance the damper state machine by one tick.
 *
 * Completes a pending travel once the bounded interval has elapsed.
 *
 * @param void No parameters.
 * @return void
 */
void damper_tick(void);

/**
 * @brief Force the vent open and record the fault.
 *
 * This is the fail-open posture taken when the control link is lost or a
 * vent frame cannot be authorized.
 *
 * @param void No parameters.
 * @return void
 */
void damper_fail_safe(void);

#endif // DAMPER_H
