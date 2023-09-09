// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Abby Cin
 * Mail: abbytsing@gmail.com
 * Create Time: 2023-09-03 17:49:27
 */

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include "hdr.h"
#include "pool.h"

#define TASKQ_DEPTH 128U

struct task {
	struct req_hdr *hdr;
	uint16_t sent_sgl;
	uint16_t recv_sgl;
	int fd;
	TAILQ_ENTRY(task) link;
};

TAILQ_HEAD(taskq, task);

struct conn {
	struct rdma_cm_id *id;
	struct ibv_cq *cq;
	struct taskq free_taskq;
	struct taskq taskq;
	struct taskq readq;
	recvq_t rxq;
	sendq_t txq;
	uint32_t file_map;
	struct task *task[TASKQ_DEPTH];
	recv_wr_t rwrs[WR_DEPTH];
	send_wr_t twrs[WR_DEPTH];
	struct ibv_sge rsges[WR_DEPTH];
	struct ibv_sge tsges[WR_DEPTH];
};

struct context {
	struct ibv_context *rdma;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct rdma_event_channel *ch;
	struct rdma_cm_id *listen_id;
	struct conn conn;
};

static bool file_mapped(uint32_t map, uint32_t id)
{
	return map & (1 << id);
}

static void file_map(uint32_t *map, uint32_t id)
{
	*map |= (1 << id);
}

static int post_recv(struct conn *c, struct ibv_recv_wr *w)
{
	recv_wr_t *wr = container_of(w, recv_wr_t, wr);
	struct context *ctx = container_of(c, struct context, conn);
	int rc = 0;
	struct ibv_recv_wr *bad;

	assert(w->sg_list);

	w->next = NULL;
	wr->pp_wr.type = OP_RDMA_RECV;
	w->wr_id = (uint64_t)(&wr->pp_wr);
	assert(w->wr_id != 0);
	w->num_sge = 1;
	assert(!w->sg_list->addr);
	w->sg_list->addr = (uint64_t)pool_get();
	assert(w->sg_list->addr);
	w->sg_list->length = ELEM_SZ;
	w->sg_list->lkey = ctx->mr->lkey;

	rc = ibv_post_recv(c->id->qp, w, &bad);
	if (rc) {
		debug("ibv_post_recv fail rc %d errno %d", rc, errno);
		return -1;
	}
	return 0;
}

static void init_resource(struct context *ctx)
{
	int num = 0;
	struct task *t;
	int _nou rc;
	struct ibv_context **ctxs = rdma_get_devices(&num);

	bzero(ctx, sizeof(*ctx));
	assert(num != 0);
	ctx->rdma = ctxs[0];

	ctx->pd = ibv_alloc_pd(ctx->rdma);
	assert(ctx->pd);

	rdma_free_devices(ctxs);

	rc = pool_init(1U << 20);
	assert(rc == 0);

	void *mem = NULL;
	size_t len = 0;

	pool_region(&mem, &len);
	assert(mem != NULL);
	assert(len != 0);

	ctx->mr = ibv_reg_mr(ctx->pd,
			     mem,
			     len,
			     IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
				     IBV_ACCESS_REMOTE_WRITE);
	assert(ctx->mr);

	TAILQ_INIT(&ctx->conn.free_taskq);
	TAILQ_INIT(&ctx->conn.taskq);
	TAILQ_INIT(&ctx->conn.readq);

	for (uint32_t i = 0; i < WR_DEPTH; ++i) {
		ctx->conn.rwrs[i].wr.num_sge = 1;
		ctx->conn.rwrs[i].wr.sg_list = &ctx->conn.rsges[i];
		rxq_push(&ctx->conn.rxq, &ctx->conn.rwrs[i].wr);

		ctx->conn.twrs[i].wr.num_sge = 1;
		ctx->conn.twrs[i].wr.sg_list = &ctx->conn.tsges[i];
		txq_push(&ctx->conn.txq, &ctx->conn.twrs[i].wr);

		t = calloc(1, sizeof(*t));
		assert(t);
		ctx->conn.task[i] = t;
		TAILQ_INSERT_TAIL(&ctx->conn.free_taskq, t, link);
	}
}

static void fini_resource(struct context *ctx)
{
	rdma_destroy_qp(ctx->conn.id);
	rdma_destroy_id(ctx->conn.id);
	rdma_destroy_id(ctx->listen_id);
	rdma_destroy_event_channel(ctx->ch);
	ibv_destroy_cq(ctx->conn.cq);
	ibv_dereg_mr(ctx->mr);
	ibv_dealloc_pd(ctx->pd);
	pool_exit();

	for (uint32_t i = 0; i < WR_DEPTH; ++i)
		free(ctx->conn.task[i]);
}

static void prepare_env(struct conn *c)
{
	struct ibv_recv_wr *w;
	int _nou rc;

	while (!rxq_empty(&c->rxq)) {
		w = rxq_head(&c->rxq);
		rxq_pop(&c->rxq);
		rc = post_recv(c, w);
		assert(rc == 0);
	}
}

static void create_conn(struct context *ctx, char *ip, char *port)
{
	int _nou rc;
	struct rdma_addrinfo *addr = NULL,
			     hints = {
				     .ai_port_space = RDMA_PS_TCP,
				     .ai_flags = RAI_PASSIVE,
			     };
	struct rdma_cm_event *ev = NULL;

	rc = rdma_getaddrinfo(ip, port, &hints, &addr);
	assert(rc == 0);

	ctx->ch = rdma_create_event_channel();
	assert(ctx->ch);

	rc = rdma_create_id(ctx->ch, &ctx->listen_id, NULL, RDMA_PS_TCP);
	assert(rc == 0);

	rc = rdma_bind_addr(ctx->listen_id, addr->ai_src_addr);
	assert(rc == 0);
	rdma_freeaddrinfo(addr);

	rc = rdma_listen(ctx->listen_id, SOMAXCONN);
	assert(rc == 0);

	rc = rdma_get_cm_event(ctx->ch, &ev);
	assert(rc == 0);

	assert(ev->event == RDMA_CM_EVENT_CONNECT_REQUEST);
	ctx->conn.id = ev->id;

	rc = rdma_ack_cm_event(ev);
	assert(rc == 0);

	assert(ctx->rdma == ctx->conn.id->verbs);
	ctx->conn.cq = ibv_create_cq(ctx->rdma, WR_DEPTH * 2, NULL, NULL, 0);
	assert(ctx->conn.cq);

	struct ibv_qp_init_attr qp_attr = {
		.qp_type = IBV_QPT_RC,
		.recv_cq = ctx->conn.cq,
		.send_cq = ctx->conn.cq,
		.cap = {
			.max_send_sge = 1,
			.max_recv_sge = 1,
			.max_send_wr = WR_DEPTH,
			.max_recv_wr = WR_DEPTH,
		},
		.sq_sig_all = 1, // always signal
	};
	rc = rdma_create_qp(ctx->conn.id, ctx->pd, &qp_attr);
	assert(rc == 0);

	struct rdma_conn_param param = {
		.initiator_depth = WR_DEPTH,
		.responder_resources = WR_DEPTH,
		.private_data = NULL,
		.private_data_len = 0,
		.retry_count = 3,
		.rnr_retry_count = 7,
	};

	prepare_env(&ctx->conn);

	rc = rdma_accept(ctx->conn.id, &param);
	assert(rc == 0);

	rc = rdma_get_cm_event(ctx->ch, &ev);
	assert(rc == 0);

	assert(ev->event == RDMA_CM_EVENT_ESTABLISHED);
	rc = rdma_ack_cm_event(ev);
	assert(rc == 0);

	int flags = fcntl(ctx->ch->fd, F_GETFL);
	rc = fcntl(ctx->ch->fd, F_SETFL, flags | O_NONBLOCK);
	assert(rc == 0);
	debug("connection established");
}

// response sent to remote
static int on_send(struct conn *c, send_wr_t *tx)
{
	struct ibv_send_wr *w = &tx->wr;
	void *mem = (void *)w->sg_list->addr;
	struct rsp_hdr _nou *h = mem;

	debug("req %u responsed", h->req_id);
	assert(h->req_id != 0);

	pool_put(mem);
	txq_push(&c->txq, w);
	return 0;
}

// request received from remote
static int on_recv(struct conn *c, recv_wr_t *rx)
{
	struct ibv_recv_wr *wr = &rx->wr;
	struct req_hdr *hdr = (void *)wr->sg_list->addr;
	char name[20] = { 0 };
	struct task *task;
	uint16_t fid = hdr->fid;

	bzero(wr->sg_list, sizeof(*wr->sg_list));
	if (post_recv(c, wr))
		return -1;

	if (TAILQ_EMPTY(&c->free_taskq)) {
		debug("no mem");
		return -1;
	}
	task = TAILQ_FIRST(&c->free_taskq);
	TAILQ_REMOVE(&c->free_taskq, task, link);

	snprintf(name, sizeof(name), "rx_%u", fid);
	if (!file_mapped(c->file_map, fid)) {
		debug("create file %s", name);
		task->fd = open(name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
		file_map(&c->file_map, fid);
	} else {
		task->fd = open(name, O_WRONLY, 0644);
	}
	if (task->fd < 0) {
		debug("open %s fail rc %d errno %d", name, task->fd, errno);
		goto err_open;
	}

	task->hdr = hdr;
	task->sent_sgl = 0;
	task->recv_sgl = 0;
	TAILQ_INSERT_TAIL(&c->taskq, task, link);

	return 0;
err_open:
	return -1;
}

static int post_response(struct conn *c, uint32_t req_id)
{
	struct context *ctx = container_of(c, struct context, conn);
	struct ibv_send_wr *w = txq_head(&c->txq), *bad;
	struct rsp_hdr *hdr = pool_get();

	send_wr_t *wr;
	int rc;

	// since we recycled memory before allocating here
	assert(w);
	assert(hdr);

	txq_pop(&c->txq);

	hdr->req_id = req_id;

	wr = container_of(w, send_wr_t, wr);
	wr->pp_wr.type = OP_RDMA_SEND;

	w->wr_id = (uint64_t)(&wr->pp_wr);
	assert(w->wr_id != 0);
	w->opcode = IBV_WR_SEND;
	w->num_sge = 1;
	w->sg_list->addr = (uint64_t)hdr;
	w->sg_list->length = sizeof(*hdr);
	w->sg_list->lkey = ctx->mr->lkey;
	w->next = NULL;

	rc = ibv_post_send(c->id->qp, w, &bad);
	if (rc) {
		debug("ibv_post_send fail rc %d errno %d", rc, errno);
		return -1;
	}
	return 0;
}

static int on_read(struct conn *c, send_wr_t *tx)
{
	struct task *t = tx->context;
	struct ibv_sge *sge = tx->wr.sg_list;
	int rc = 0;
	ssize_t _nou n;

	assert(t);

	debug("req %u laddr %#lx raddr %#lx bytes %u offset %lu",
	      t->hdr->req_id,
	      sge->addr,
	      tx->addr,
	      sge->length,
	      tx->offset);
	n = pwrite(t->fd, (void *)sge->addr, sge->length, tx->offset);
	pool_put((void *)sge->addr);
	txq_push(&c->txq, &tx->wr);
	t->recv_sgl += 1;
	if (t->recv_sgl == t->hdr->nr_sgl) {
		uint32_t id = t->hdr->req_id;

		close(t->fd);
		pool_put(t->hdr);
		rc = post_response(c, id);
		TAILQ_REMOVE(&c->readq, t, link);
		TAILQ_INSERT_TAIL(&c->free_taskq, t, link);
	}

	return rc;
}

static int post_read(struct conn *c, struct task *t)
{
	int rc;
	struct ibv_send_wr *w = NULL, *bad;
	struct context *ctx = container_of(c, struct context, conn);
	send_wr_t *wr;
	void *mem;
	struct xfer_sgl *sgl;
	struct ibv_send_wr d = { 0 }, *p;

	p = &d;
	p->next = NULL;
	while (t->sent_sgl < t->hdr->nr_sgl && !txq_empty(&c->txq)) {
		mem = pool_get();
		if (!mem)
			break;

		w = txq_head(&c->txq);
		txq_pop(&c->txq);

		sgl = &t->hdr->sgl[t->sent_sgl];
		wr = container_of(w, send_wr_t, wr);
		wr->pp_wr.type = OP_RDMA_READ;

		w->next = NULL;
		w->num_sge = 1;
		w->opcode = IBV_WR_RDMA_READ;
		w->wr_id = (uint64_t)(&wr->pp_wr);
		assert(w->wr_id != 0);

		w->wr.rdma.remote_addr = sgl->addr;
		w->wr.rdma.rkey = sgl->rkey;

		assert(sgl->length <= ELEM_SZ);
		w->sg_list->addr = (uint64_t)mem;
		w->sg_list->length = sgl->length;
		w->sg_list->lkey = ctx->mr->lkey;

		wr->offset = sgl->offset;
		wr->addr = sgl->addr;
		wr->context = t;
		t->sent_sgl += 1;

		p->next = w;
		p = p->next;
	}

	if (d.next) {
		rc = ibv_post_send(c->id->qp, d.next, &bad);
		if (rc) {
			debug("ibv_post_send fail rc %d errno %d", rc, errno);
			return -1;
		}
	}
	return 0;
}

static int process_task(struct conn *c)
{
	struct task *t, *tvar;
	TAILQ_FOREACH_SAFE (t, &c->taskq, link, tvar) {
		if (post_read(c, t))
			return -1;
		if (t->sent_sgl == t->hdr->nr_sgl) {
			TAILQ_REMOVE(&c->taskq, t, link);
			TAILQ_INSERT_TAIL(&c->readq, t, link);
		}
	}
	return 0;
}

static int process_cm_event(struct conn *c)
{
	struct context *ctx = container_of(c, struct context, conn);
	struct rdma_cm_event *ev;
	int rc = 0;

	errno = 0;
	rc = rdma_get_cm_event(ctx->ch, &ev);
	if (rc) {
		if (errno != EAGAIN) {
			debug("rdma_get_cm_event rc %d errno %d", rc, errno);
			return -1;
		}
		return 0;
	}
	switch (ev->event) {
	case RDMA_CM_EVENT_DISCONNECTED:
		debug("disconnect");
		rdma_disconnect(c->id);
		rdma_ack_cm_event(ev);
		return 1;
	default:
		debug("cm_event %d", ev->event);
		rdma_ack_cm_event(ev);
	}
	return 0;
}

static int process_cq(struct conn *c, struct ibv_wc *wc, int n)
{
	int rc = 0;
	struct pp_wr *pw;
	send_wr_t *tx;
	recv_wr_t *rx;

	for (int i = 0; i < n; ++i) {
		if (wc[i].status != 0) {
			debug("wc error %s", ibv_wc_status_str(wc[i].status));
			return -1;
		}
		pw = (void *)wc[i].wr_id;
		switch (pw->type) {
		case OP_RDMA_SEND:
			tx = container_of(pw, send_wr_t, pp_wr);
			rc = on_send(c, tx);
			break;
		case OP_RDMA_RECV:
			rx = container_of(pw, recv_wr_t, pp_wr);
			rc = on_recv(c, rx);
			break;
		case OP_RDMA_READ:
			tx = container_of(pw, send_wr_t, pp_wr);
			rc = on_read(c, tx);
			break;
		}
	}
	return rc;
}

static int recv_file(struct conn *c)
{
	struct ibv_wc wc[WR_DEPTH];
	int rc = 0;

	while (true) {
		if (process_task(c))
			break;
		rc = process_cm_event(c);
		if (rc != 0)
			break;
		rc = ibv_poll_cq(c->cq, WR_DEPTH, wc);
		if (rc < 0) {
			debug("ibv_poll_cq fail rc %d errno %d", rc, errno);
			return -1;
		}
		if (rc == 0)
			continue;
		rc = process_cq(c, wc, rc);
		if (rc)
			break;
	}
	return rc;
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		debug("%s ip port", argv[0]);
		return 1;
	}

	struct context ctx;
	char *ip = argv[1];
	char *port = argv[2];
	int rc;

	init_resource(&ctx);
	create_conn(&ctx, ip, port);

	rc = recv_file(&ctx.conn);

	fini_resource(&ctx);
	return rc < 0 ? 1 : 0;
}
