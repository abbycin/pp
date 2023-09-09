// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Abby Cin
 * Mail: abbytsing@gmail.com
 * Create Time: 2023-09-03 16:21:34
 */

#include "pool.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define MIN_ELEM_COUNT 32U

struct elem {
	struct elem *link;
	char data[ELEM_SZ - sizeof(void *)];
};

struct pool {
	char *mem;
	struct elem *head;
	size_t elem_cnt;
	size_t size;
};

static struct pool g_pool;

static inline uint64_t elem_id(void *start, void *elem)
{
	return ((uint64_t)elem - (uint64_t)start) >> ELEM_SHIFT;
}

int pool_init(size_t bytes)
{
	uint32_t nr_elem = bytes >> ELEM_SHIFT;
	if (nr_elem < MIN_ELEM_COUNT) {
		debug("%zu too small, at least %u",
		      bytes,
		      MIN_ELEM_COUNT * ELEM_SZ);
		return 1;
	}

	bzero(&g_pool, sizeof(g_pool));

	int rc = posix_memalign((void **)&g_pool.mem, ELEM_SZ, bytes);
	if (rc) {
		debug("posix_memalign fail rc %d errno %d", rc, errno);
		return -1;
	}
	assert(((uint64_t)g_pool.mem & ELEM_MASK) == 0);

	struct elem *p = (struct elem *)g_pool.mem;
	for (uint32_t i = 0; i < nr_elem; ++i) {
		p->link = g_pool.head;
		g_pool.head = p;
		p += 1;
	}
	g_pool.size = bytes;
	g_pool.elem_cnt = nr_elem;
	return 0;
}

void pool_region(void **start, size_t *size)
{
	*start = g_pool.mem;
	*size = g_pool.size;
}

void *pool_get(void)
{
	if (g_pool.elem_cnt == 0)
		return NULL;
	struct elem *r = g_pool.head;
	g_pool.head = g_pool.head->link;
	g_pool.elem_cnt -= 1;
	r->link = NULL;
	return r;
}

void pool_put(void *arg)
{
	struct elem *p = arg;
	p->link = g_pool.head;
	g_pool.head = p;
	g_pool.elem_cnt += 1;
}

void pool_exit(void)
{
	free(g_pool.mem);
	bzero(&g_pool, sizeof(g_pool));
}
