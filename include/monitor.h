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
// File:    monitor.h
// Desc:    Declares the vent controller state machine tying the local
//          maintenance remote, the sealed vent command path, the rack
//          temperature sensor, the vent damper, and the vault control
//          gateway link together.
// Created: 2026

#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Onboard heartbeat LED pulse width in microseconds.
 */
#define MONITOR_HEARTBEAT_US 2000u

/**
 * @brief Initialize the vent controller state machine.
 *
 * Configures the I2C LCD, the DHT11 rack temperature sensor, the
 * infrared maintenance remote, the tower light lamps, the vent damper
 * servo, the manual purge button, the RYLR998 radio, and derives the
 * Argon2id field key.
 *
 * @param void No parameters.
 * @return bool true when all submodules initialized.
 */
bool monitor_init(void);

/**
 * @brief Clear the node-ready flag and command path.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_deinit(void);

/**
 * @brief Clear a pending manual purge request.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_purge_request(void);

/**
 * @brief Execute one vent controller tick.
 *
 * Polls the maintenance remote and the radio, verifies and applies
 * sealed vent commands, drives the damper and tower light, renders the
 * vault status, and fails open to the safe cooling posture on a lost
 * control link. A manual purge never bypasses authorization and
 * untrusted frames are never applied.
 *
 * @param void No parameters.
 * @return bool true when the tick completed without a policy error.
 */
bool monitor_step(void);

#endif // MONITOR_H
