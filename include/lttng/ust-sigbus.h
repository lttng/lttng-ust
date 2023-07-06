// SPDX-FileCopyrightText: 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: GPL-2.0-only

#ifndef _LTTNG_UST_SIGBUS_H
#define _LTTNG_UST_SIGBUS_H

#include <urcu/list.h>
#include <setjmp.h>

struct lttng_ust_sigbus_range {
	void *start;	/* inclusive */
	void *end;	/* exclusive */
	struct cds_list_head node;
};

struct lttng_ust_sigbus_state {
	int jmp_ready;
	struct cds_list_head head;	/* struct lttng_ust_sigbus_range */
	sigjmp_buf sj_env;
};

/*
 * Define the lttng_ust_sigbus_state TLS variable as initial-exec model
 * to allow using it from the SIGBUS signal handler. This variable must
 * be defined by the executable using DEFINE_LTTNG_UST_SIGBUS_STATE()
 * rather than internally within liblttng-ust-ctl.so to ensure we don't
 * contribute to reach glibc limits of pre-allocated TLS IE model space
 * for shared objects.
 */
#define DEFINE_LTTNG_UST_SIGBUS_STATE()	\
	__thread __attribute__((tls_model("initial-exec"))) struct lttng_ust_sigbus_state lttng_ust_sigbus_state

extern __thread __attribute__((tls_model("initial-exec"))) struct lttng_ust_sigbus_state lttng_ust_sigbus_state;

#endif /* _LTTNG_UST_SIGBUS_H */
