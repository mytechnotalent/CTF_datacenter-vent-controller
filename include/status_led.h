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
// File:    status_led.h
// Desc:    Declares the red, yellow, and green vault status tower light.
// Created: 2026

#ifndef STATUS_LED_H
#define STATUS_LED_H

#include "vent.h"
#include <stdbool.h>

/**
 * @brief Tri-color vault status tower light states.
 */
typedef enum vent_led_state {
    /**
     * @brief All tower light lamps dark.
     */
    VENT_OFF = 0,
    /**
     * @brief Red lamp lit when the server hall is hot.
     */
    VENT_HALL_HOT = 1,
    /**
     * @brief Yellow lamp lit when the vent is ransom locked.
     */
    VENT_LOCKED = 2,
    /**
     * @brief Green lamp lit while the hall is cooling and clear.
     */
    VENT_COOLING_OK = 3,
} vent_led_state_t;

/**
 * @brief Initialize the tri-color vault status tower light GPIO pins.
 *
 * @param void No parameters.
 * @return bool true when initialization completed.
 */
bool status_led_init(void);

/**
 * @brief Drive exactly one tower light lamp for a vault state.
 *
 * @param state Desired tower light state.
 * @return void
 */
void status_led_show(vent_led_state_t state);

#endif // STATUS_LED_H
