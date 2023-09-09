// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Abby Cin
 * Mail: abbytsing@gmail.com
 * Create Time: 2023-09-03 16:21:43
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define ELEM_SZ 4096U
#define ELEM_SHIFT 12
#define ELEM_MASK 4095
#define debug(fmt, ...)                                                        \
	fprintf(stderr, "%s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

int pool_init(size_t bytes);

void pool_region(void **start, size_t *size);

void *pool_get(void);

void pool_put(void *mem);

void pool_exit(void);
