// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Abby Cin
 * Mail: abbytsing@gmail.com
 * Create Time: 2023-09-03 16:21:16
 */

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "pool.h"
#include "hdr.h"

static uint16_t g_fid;
static uint16_t g_seq = 233;

struct task {
	struct req_hdr *hdr; // point to mr memory
	int nr_sgl;
	uint32_t id;
	TAILQ_ENTRY(task) link;
};

TAILQ_HEAD(taskq, task);

struct fctx {
	uint16_t fid;
	int fd;
	uint64_t offset;
	uint64_t finish_offset;
	uint64_t size;
};

struct conn {
	struct rdma_event_channel *ch;
	struct rdma_cm_id *id;
	struct ibv_cq *cq;
	struct taskq free_taskq;
	struct taskq taskq;
	struct taskq recvq;
	recvq_t rxq;
	sendq_t txq;
	struct task *task[WR_DEPTH];
	recv_wr_t rwrs[WR_DEPTH];
	send_wr_t twrs[WR_DEPTH];
	struct ibv_sge rsges[WR_DEPTH];
	struct ibv_sge tsges[WR_DEPTH];
};

struct context {
	struct ibv_context *rdma;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct conn conn;
};

static int post_recv(struct conn *c, struct ibv_recv_wr *w)
{
	recv_wr_t *wr = container_of(w, recv_wr_t, wr);
	struct context *ctx = container_of(c, struct context, conn);
	int rc = 0;
	struct ibv_recv_wr *bad;
	void *mem = pool_get();

	assert(mem);
	assert(w->sg_list);

	bzero(mem, sizeof(struct rsp_hdr));
	wr->pp_wr.type = OP_RDMA_RECV;
	w->next = NULL;
	w->wr_id = (uint64_t)(&wr->pp_wr);
	w->num_sge = 1;
	w->sg_list->addr = (uint64_t)mem;
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
	struct ibv_context **ctxs = rdma_get_devices(&num);
	struct task *t;

	assert(num > 0);
	ctx->rdma = ctxs[0];

	ctx->pd = ibv_alloc_pd(ctx->rdma);
	assert(ctx->pd);

	rdma_free_devices(ctxs);

	int _nou rc = pool_init(1UL << 20);
	assert(rc == 0);

	void *mem = NULL;
	size_t len = 0;

	pool_region(&mem, &len);

	ctx->mr = ibv_reg_mr(ctx->pd,
			     mem,
			     len,
			     IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
				     IBV_ACCESS_REMOTE_WRITE);
	assert(ctx->mr);

	bzero(&ctx->conn, sizeof(ctx->conn));
	for (uint32_t i = 0; i < WR_DEPTH; ++i) {
		ctx->conn.rwrs[i].wr.sg_list = &ctx->conn.rsges[i];
		rxq_push(&ctx->conn.rxq, &ctx->conn.rwrs[i].wr);
	}

	for (uint32_t i = 0; i < WR_DEPTH; ++i) {
		ctx->conn.twrs[i].wr.sg_list = &ctx->conn.tsges[i];
		txq_push(&ctx->conn.txq, &ctx->conn.twrs[i].wr);
	}

	TAILQ_INIT(&ctx->conn.free_taskq);
	TAILQ_INIT(&ctx->conn.taskq);
	TAILQ_INIT(&ctx->conn.recvq);

	for (uint32_t i = 0; i < WR_DEPTH; ++i) {
		t = calloc(1, sizeof(*t));
		assert(t);
		t->id = i;
		t->hdr = pool_get();
		assert(t->hdr);
		ctx->conn.task[i] = t;
		TAILQ_INSERT_TAIL(&ctx->conn.free_taskq, t, link);
	}
}

static void fini_resource(struct context *ctx)
{
	rdma_destroy_qp(ctx->conn.id);
	rdma_destroy_id(ctx->conn.id);
	rdma_destroy_event_channel(ctx->conn.ch);
	ibv_destroy_cq(ctx->conn.cq);
	ibv_dereg_mr(ctx->mr);
	ibv_dealloc_pd(ctx->pd);
	pool_exit();

	for (uint32_t i = 0; i < WR_DEPTH; ++i)
		free(ctx->conn.task[i]);
}

static void create_conn(struct context *ctx, char *ip, char *port)
{
	int _nou rc;
	struct rdma_addrinfo *addr = NULL;
	struct rdma_cm_event *ev = NULL;

	rc = rdma_getaddrinfo(ip, port, NULL, &addr);
	assert(rc == 0);

	ctx->conn.ch = rdma_create_event_channel();
	assert(ctx->conn.ch);

	rc = rdma_create_id(ctx->conn.ch, &ctx->conn.id, NULL, RDMA_PS_TCP);
	assert(rc == 0);

	rc = rdma_resolve_addr(ctx->conn.id, NULL, addr->ai_dst_addr, 1000);
	assert(rc == 0);

	rdma_freeaddrinfo(addr);

	rc = rdma_get_cm_event(ctx->conn.ch, &ev);
	assert(rc == 0);

	assert(ev->event == RDMA_CM_EVENT_ADDR_RESOLVED);
	rc = rdma_ack_cm_event(ev);
	assert(rc == 0);

	rc = rdma_resolve_route(ctx->conn.id, 1000);
	assert(rc == 0);

	rc = rdma_get_cm_event(ctx->conn.ch, &ev);
	assert(rc == 0);

	assert(ev->event == RDMA_CM_EVENT_ROUTE_RESOLVED);
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

	struct rdma_conn_param conn_param = {
		.private_data = NULL,
		.private_data_len = 0,
		.initiator_depth = WR_DEPTH,
		.responder_resources = WR_DEPTH,
		.retry_count = 3,
		.rnr_retry_count = 7,
	};
	rc = rdma_connect(ctx->conn.id, &conn_param);
	assert(rc == 0);

	rc = rdma_get_cm_event(ctx->conn.ch, &ev);
	assert(rc == 0);

	assert(ev->event == RDMA_CM_EVENT_ESTABLISHED);

	rc = rdma_ack_cm_event(ev);
	assert(rc == 0);
	struct ibv_recv_wr *w;

	while (!rxq_empty(&ctx->conn.rxq)) {
		w = rxq_head(&ctx->conn.rxq);
		rxq_pop(&ctx->conn.rxq);
		rc = post_recv(&ctx->conn, w);
		assert(rc == 0);
	}
	int flags = fcntl(ctx->conn.ch->fd, F_GETFL);
	rc = fcntl(ctx->conn.ch->fd, F_SETFL, flags | O_NONBLOCK);
	assert(rc == 0);
	debug("connection established");
}

static void on_send(struct conn *c, send_wr_t *tx)
{
	// NOTE: `task`、`hdr` and `addr` in sgl will be recycled in `on_recv`
	txq_push(&c->txq, &tx->wr);
}

static int on_recv(struct conn *c, recv_wr_t *rx, struct fctx *fctx)
{
	struct ibv_recv_wr *w = &rx->wr;
	struct rsp_hdr *rsp = (void *)w->sg_list->addr;
	struct req_hdr *req;
	struct task *t;
	uint32_t task_idx = decode_req_id(rsp->req_id);

	assert(rsp->req_id != 0);
	assert(task_idx < WR_DEPTH);
	t = c->task[task_idx];
	req = t->hdr;
	assert(rsp->req_id == req->req_id);
	assert(req->nr_sgl);

	for (uint16_t i = 0; i < req->nr_sgl; ++i) {
		pool_put((void *)req->sgl[i].addr);
		fctx->finish_offset += req->sgl[i].length;
	}

	bzero(t->hdr, sizeof(*t->hdr));
	TAILQ_REMOVE(&c->recvq, t, link);
	TAILQ_INSERT_TAIL(&c->free_taskq, t, link);

	bzero(rsp, sizeof(*rsp));
	pool_put(rsp);

	return post_recv(c, w);
}

static int post_send(struct conn *c, struct task *t, uint32_t lkey)
{
	int rc;
	struct ibv_send_wr *w, *bad;
	send_wr_t *wr;

	assert(!txq_empty(&c->txq));
	w = txq_head(&c->txq);
	txq_pop(&c->txq);

	wr = container_of(w, send_wr_t, wr);
	wr->context = t;
	wr->pp_wr.type = OP_RDMA_SEND;

	w->wr_id = (uint64_t)(&wr->pp_wr);
	w->opcode = IBV_WR_SEND;
	w->num_sge = 1;

	w->sg_list->addr = (uint64_t)t->hdr;
	w->sg_list->length = sizeof(*t->hdr);
	w->sg_list->lkey = lkey;
	w->next = NULL;

	rc = ibv_post_send(c->id->qp, w, &bad);
	if (rc) {
		debug("ibv_post_send rc %d errno %d", rc, errno);
		return -1;
	}
	return 0;
}

static int fill_task(struct task *t, struct fctx *fctx, uint32_t rkey)
{
	struct req_hdr *hdr;
	void *mem;
	uint32_t bytes;
	int cnt = 0;

	hdr = t->hdr;
	while (hdr->nr_sgl < SGL_PER_IO && fctx->offset < fctx->size) {
		mem = pool_get();
		if (!mem)
			goto done;

		if (!t->hdr->req_id) {
			t->hdr->req_id = build_req_id(t->id, g_seq++);
			t->hdr->fid = fctx->fid;
		}
		bytes = min(ELEM_SZ, fctx->size - fctx->offset);
		int64_t _nou n = read(fctx->fd, mem, bytes);
		assert((uint32_t)n == bytes);
		debug("req %u addr %p bytes %u offset %lu",
		      hdr->req_id,
		      mem,
		      bytes,
		      fctx->offset);
		hdr->sgl[hdr->nr_sgl].addr = (uint64_t)mem;
		hdr->sgl[hdr->nr_sgl].rkey = rkey;
		hdr->sgl[hdr->nr_sgl].length = bytes;
		hdr->sgl[hdr->nr_sgl].offset = fctx->offset;
		hdr->nr_sgl += 1;
		fctx->offset += bytes;
		cnt += 1;
	}
done:
	return cnt;
}

static int process_cm_event(struct conn *c)
{
	struct rdma_cm_event *ev;
	int rc = 0;

	errno = 0;
	rc = rdma_get_cm_event(c->ch, &ev);
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

static void prepare_task(struct conn *c, struct fctx *fctx)
{
	struct task *t;
	struct context *ctx = container_of(c, struct context, conn);

	while (!TAILQ_EMPTY(&c->free_taskq)) {
		t = TAILQ_FIRST(&c->free_taskq);
		assert(t->hdr);

		if (fill_task(t, fctx, ctx->mr->rkey)) {
			assert(t->hdr->nr_sgl);
			TAILQ_REMOVE(&c->free_taskq, t, link);
			TAILQ_INSERT_TAIL(&c->taskq, t, link);
		} else {
			break;
		}
	}
}

static int process_task(struct conn *c)
{
	struct context *ctx = container_of(c, struct context, conn);
	struct task *t, *tvar;
	int rc;

	TAILQ_FOREACH_SAFE (t, &c->taskq, link, tvar) {
		if (txq_empty(&c->txq)) {
			debug("no mem");
			break;
		}
		rc = post_send(c, t, ctx->mr->lkey);
		if (rc == -1)
			return -1;
		TAILQ_REMOVE(&c->taskq, t, link);
		TAILQ_INSERT_TAIL(&c->recvq, t, link);
	}

	return 0;
}

static int process_cq(struct conn *c, struct fctx *f, struct ibv_wc *wc, int n)
{
	int rc = 0;
	struct pp_wr *pw;
	recv_wr_t *rx;
	send_wr_t *tx;

	for (int i = 0; i < n; ++i) {
		if (wc[i].status != 0) {
			debug("wc error %s", ibv_wc_status_str(wc[i].status));
			return -1;
		}
		pw = (void *)wc[i].wr_id;
		switch (pw->type) {
		case OP_RDMA_SEND:
			tx = container_of(pw, send_wr_t, pp_wr);
			on_send(c, tx);
			break;
		case OP_RDMA_RECV:
			rx = container_of(pw, recv_wr_t, pp_wr);
			rc = on_recv(c, rx, f);
			break;
		default:
			debug("unexpected type %d", pw->type);
			rc = -1;
		}
	}

	return rc;
}

static int transfer_file(struct conn *c, struct fctx *fctx)
{
	struct ibv_wc wc[WR_DEPTH];
	int rc = 0;

	while (fctx->finish_offset < fctx->size) {
		rc = process_cm_event(c);
		if (rc != 0)
			return -1;
		prepare_task(c, fctx);
		rc = process_task(c);
		if (rc)
			return -1;
		rc = ibv_poll_cq(c->cq, WR_DEPTH, wc);
		if (rc < 0) {
			debug("ibv_poll_cq fail rc %d errno %d", rc, errno);
			return -1;
		}
		if (rc == 0)
			continue;
		rc = process_cq(c, fctx, wc, rc);
		if (rc)
			return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		debug("%s ip port paths", argv[0]);
		return 1;
	}
	char *ip = argv[1];
	char *port = argv[2];
	char **paths = &argv[3];
	int nr_path = argc - 3;
	int rc = 1;
	struct context ctx = { 0 };
	struct fctx fctx = { 0 };
	struct stat st;

	init_resource(&ctx);
	create_conn(&ctx, ip, port);

	for (int i = 0; i < nr_path; ++i) {
		bzero(&st, sizeof(st));
		bzero(&fctx, sizeof(fctx));
		rc = stat(paths[i], &st);
		if (rc) {
			debug("stat %s fail rc %d errno %d",
			      paths[i],
			      rc,
			      errno);
			continue;
		}
		fctx.fd = open(paths[i], O_RDONLY);
		if (fctx.fd < 0) {
			debug("open %s fail rc %d errno %d",
			      paths[i],
			      fctx.fd,
			      errno);
			continue;
		}
		fctx.size = st.st_size;
		fctx.fid = g_fid++;
		rc = transfer_file(&ctx.conn, &fctx);
		if (rc)
			break;
	}

	if (fctx.fd)
		close(fctx.fd);
	fini_resource(&ctx);
	return rc != 0;
}
