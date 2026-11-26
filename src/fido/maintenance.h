/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 */

#ifndef MAINTENANCE_H
#define MAINTENANCE_H

#include <stdbool.h>
#include <stdint.h>

/* RAM-only batch window. Power loss clears it. An open window lets
 * password write/delete and SSH credential create/delete skip the
 * per-item button. Idle 3s (reset on each skip); hard max 2 minutes
 * from open. Typing a password and signing in still wait. */

bool maintenance_active(void);
void maintenance_open(void);
void maintenance_close(void);
uint16_t maintenance_remaining_s(void);
bool maintenance_skip_button(void);

#endif
