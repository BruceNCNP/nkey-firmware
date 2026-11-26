/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
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

#ifndef __VERSION_H_
#define __VERSION_H_

#ifndef PICO_FIDO_VERSION_MAJOR
#define PICO_FIDO_VERSION_MAJOR 1
#endif
#ifndef PICO_FIDO_VERSION_MINOR
#define PICO_FIDO_VERSION_MINOR 0
#endif
#ifndef PICO_FIDO_VERSION_PATCH
#define PICO_FIDO_VERSION_PATCH 0
#endif

#define PICO_FIDO_VERSION (((PICO_FIDO_VERSION_MAJOR & 0xff) << 8) | (PICO_FIDO_VERSION_MINOR & 0xff))

#endif
