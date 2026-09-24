# datacenter-vent-controller - Design Blueprint (Act VIII, IRON VAULT)

Repo: `datacenter-vent-controller`
Companion CTF repo: `CTF_datacenter-vent-controller` (artifact prefix `ACT-VIII`)
Codename: IRON VAULT
Author: Kevin Thomas (kevin@mytechnotalent.com)

## Act VIII of the OPERATION COLD IRON saga

Act I the lie. Act II the door. Act III the payload. Act IV the payload that
would not die. Act V the payload that spreads. Act VI the payload that steals.
Act VII the payload that takes orders. Act VIII is the payload that holds the
building hostage.

The datacenter vent controller keeps the server hall cool. FROSTLINE's implant
locks the vent shut until a condition is met (availability attack / ransom
logic): the hall heats, the racks throttle, and the operator is told the vent is
"maintenance locked". WHITEOUT must break the lock and restore the vent. This is
the availability lesson.

## Safety contract

- No network, no internet, no host impact. Bare-metal RP2350, no OS.
- The "lock" affects only the mock vent servo and LCD. No real data is held.
- Synthetic data only. No external address.
- A `SANDBOX_ONLY` build guard disables the implant.
- Every act ends in analysis and neutralization.

## Parity contract

Same layout, crypto, tooling, pin map, README standard, disclaimer, and REAL
flash persistence (0x103FF000) as Acts I-VII.

## Pin map (identical, new roles)

| Pin | Act VIII role |
| --- | ------------- |
| DHT11 GP4 | rack temperature |
| LCD SDA GP2 / SCL GP3 | vault lock status |
| IR GP5 | local maintenance remote |
| Servo GP14 | vent damper |
| Red GP16 | HALL HOT |
| Yellow GP17 | LOCKED |
| Green GP18 | COOLING OK |
| Button GP15 | manual purge |
| RYLR998 GP8/9 | BMS link |
| Debug Probe | ransom-logic analysis |
| Onboard GP25 | heartbeat |

## Fix track

- Vent commands must be sealed and authorized.
- Manual purge must not silently bypass authorization.
- The vent must fail open (safe) on a lost link.

## Malware track (availability / ransom logic, benign)

Module `include/implant.h` + `src/implant.c`, only under `SANDBOX_ONLY`:

- **Lock.** Force the vent closed and mask the true state as "maintenance".
- **Release condition.** Unlock only on a magic release token (or never).
- **Lock marker.** Program a lock marker into the reserved flash sector
  (`DATACENTER_IMPLANT_RESERVE_ADDR` 0x103FF000) with the real flash API.
- **Anti-debug.** Reads DHCSR and behaves benignly under a probe.
- **Neutralization.** Break the lock, restore the vent, clear the marker.

## Companion CTF: ACT-VIII, four deep tasks

| Task | Points | Objective |
| ---- | ------ | --------- |
| 1 | 10 | Setup and analysis |
| 2 | 20 | Break the vent lock |
| 3 | 20 | Restore the true LCD state (unmask) |
| 4 | 20 | Clear the lock marker |
| 5 | 20 | Seal the vent command path (fix track) |
| 6 | 10 | Export, verify, hardware proof, reflection |

Every patch is in-place and same-size.

## Naming

Project `datacenter-vent-controller`; companion
`CTF_datacenter-vent-controller`; prefix `ACT-VIII`.
