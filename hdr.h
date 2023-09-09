// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Abby Cin
 * Mail: abbytsing@gmail.com
 * Create Time: 2023-09-03 16:20:59
 */

#pragma once

#include <infiniband/verbs.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SGL_PER_IO 16U
#define WR_DEPTH 16U
#define MAX_FILE 32U
#define _nou __attribute__((unused))

struct xfer_sgl {
	uint32_t rkey;
	uint32_t length;
	uint64_t addr;
	uint64_t offset;
};

struct req_hdr {
	uint32_t req_id;
	uint16_t nr_sgl;
	uint16_t fid;
	struct xfer_sgl sgl[SGL_PER_IO];
};

struct rsp_hdr {
	uint32_t req_id;
	uint32_t pad;
};

#define container_of(ptr, type, member)                                        \
	({                                                                     \
		typeof(((type *)0)->member) *__mptr = (ptr);                   \
		(type *)((char *)__mptr - offsetof(type, member));             \
	})

#define min(x, y)                                                              \
	({                                                                     \
		typeof(x) _x = (x);                                            \
		typeof(y) _y = (y);                                            \
		_x > _y ? _y : _x;                                             \
	})

#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                             \
	for ((var) = TAILQ_FIRST((head));                                      \
	     (var) && ((tvar) = TAILQ_NEXT((var), field), 1);                  \
	     (var) = (tvar))

enum wr_type {
	OP_RDMA_READ = 3,
	OP_RDMA_SEND = 5,
	OP_RDMA_RECV = 7,
};

struct pp_wr {
	enum wr_type type;
};

typedef struct {
	struct pp_wr pp_wr;
	uint64_t addr;
	uint64_t offset;
	struct ibv_send_wr wr;
	void *context;
} send_wr_t;

typedef struct {
	struct pp_wr pp_wr;
	struct ibv_recv_wr wr;
} recv_wr_t;

typedef struct {
	struct ibv_send_wr *head;
	struct ibv_send_wr *tail;
} sendq_t;

typedef struct {
	struct ibv_recv_wr *head;
	struct ibv_recv_wr *tail;
} recvq_t;

static inline bool txq_empty(sendq_t *q)
{
	return q->head == NULL;
}

static inline struct ibv_send_wr *txq_head(sendq_t *q)
{
	return q->head;
}

static inline void txq_push(sendq_t *q, struct ibv_send_wr *w)
{
	w->next = NULL;
	if (q->head == NULL) {
		q->head = w;
		q->tail = w;
	} else {
		q->tail->next = w;
		q->tail = w;
	}
}

static inline void txq_pop(sendq_t *q)
{
	struct ibv_send_wr *r = q->head;

	if (r) {
		q->head = r->next;
		r->next = NULL;
	}
}

static inline bool rxq_empty(recvq_t *q)
{
	return q->head == NULL;
}

static inline struct ibv_recv_wr *rxq_head(recvq_t *q)
{
	return q->head;
}

static inline void rxq_push(recvq_t *q, struct ibv_recv_wr *w)
{
	w->next = NULL;
	if (q->head == NULL) {
		q->head = w;
		q->tail = w;
	} else {
		q->tail->next = w;
		q->tail = w;
	}
}

static inline void rxq_pop(recvq_t *q)
{
	struct ibv_recv_wr *r = q->head;

	if (r) {
		q->head = r->next;
		r->next = NULL;
	}
}

static inline uint32_t decode_req_id(uint32_t id)
{
	return id >> 16;
}

static inline uint32_t build_req_id(uint32_t task_id, uint16_t seq)
{
	return (task_id << 16) | seq;
}
