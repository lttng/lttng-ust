/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2020 (C) Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _LTTNG_UST_CONTEXT_INTERNAL_H
#define _LTTNG_UST_CONTEXT_INTERNAL_H

#include <lttng/ust-events.h>
#include "ust-helper.h"
#include "ust-events-internal.h"

LTTNG_HIDDEN
int lttng_context_init_all(struct lttng_ctx **ctx);

LTTNG_HIDDEN
int lttng_attach_context(struct lttng_ust_abi_context *context_param,
		union lttng_ust_abi_args *uargs,
		struct lttng_ctx **ctx, struct lttng_session *session);

LTTNG_HIDDEN
int lttng_find_context(struct lttng_ctx *ctx, const char *name);
LTTNG_HIDDEN
int lttng_get_context_index(struct lttng_ctx *ctx, const char *name);
LTTNG_HIDDEN
struct lttng_ctx_field *lttng_append_context(struct lttng_ctx **ctx_p);
LTTNG_HIDDEN
void lttng_context_update(struct lttng_ctx *ctx);
LTTNG_HIDDEN
void lttng_remove_context_field(struct lttng_ctx **ctx_p,
				struct lttng_ctx_field *field);
LTTNG_HIDDEN
void lttng_destroy_context(struct lttng_ctx *ctx);

LTTNG_HIDDEN
int lttng_context_add_rcu(struct lttng_ctx **ctx_p,
		const struct lttng_ctx_field *f);

LTTNG_HIDDEN
int lttng_context_is_app(const char *name);

LTTNG_HIDDEN
void lttng_context_vtid_reset(void);
LTTNG_HIDDEN
void lttng_context_vpid_reset(void);
LTTNG_HIDDEN
void lttng_context_cgroup_ns_reset(void);
LTTNG_HIDDEN
void lttng_context_ipc_ns_reset(void);
LTTNG_HIDDEN
void lttng_context_mnt_ns_reset(void);
LTTNG_HIDDEN
void lttng_context_net_ns_reset(void);
LTTNG_HIDDEN
void lttng_context_pid_ns_reset(void);
LTTNG_HIDDEN
void lttng_context_user_ns_reset(void);
LTTNG_HIDDEN
void lttng_context_uts_ns_reset(void);
LTTNG_HIDDEN
void lttng_context_time_ns_reset(void);
LTTNG_HIDDEN
void lttng_context_vuid_reset(void);
LTTNG_HIDDEN
void lttng_context_veuid_reset(void);
LTTNG_HIDDEN
void lttng_context_vsuid_reset(void);
LTTNG_HIDDEN
void lttng_context_vgid_reset(void);
LTTNG_HIDDEN
void lttng_context_vegid_reset(void);
LTTNG_HIDDEN
void lttng_context_vsgid_reset(void);

LTTNG_HIDDEN
int lttng_add_vtid_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_vpid_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_pthread_id_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_procname_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_ip_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_cpu_id_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_dyntest_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_cgroup_ns_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_ipc_ns_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_mnt_ns_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_net_ns_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_pid_ns_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_user_ns_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_uts_ns_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_time_ns_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_vuid_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_veuid_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_vsuid_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_vgid_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_vegid_to_ctx(struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_add_vsgid_to_ctx(struct lttng_ctx **ctx);

#endif /* _LTTNG_UST_CONTEXT_INTERNAL_H */
