/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <urcu/tls-compat.h>
#include <lttng/ust-cancelstate.h>

#include "common/logging.h"

struct ust_cancelstate {
	int nesting;
	int oldstate;	/* oldstate for outermost nesting */
};

static DEFINE_URCU_TLS(struct ust_cancelstate, thread_state);

int lttng_ust_cancelstate_disable_push(void)
{
	struct ust_cancelstate *state = &URCU_TLS(thread_state);
	int ret, oldstate;

	if (state->nesting++)
		goto end;
	ret = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	if (ret) {
		ERR("pthread_setcancelstate: ret=%d", ret);
		return -1;
	}
	state->oldstate = oldstate;
end:
	return 0;
}

int lttng_ust_cancelstate_disable_pop(void)
{
	struct ust_cancelstate *state = &URCU_TLS(thread_state);
	int ret, oldstate;

	if (!state->nesting)
		return -1;
	if (--state->nesting)
		goto end;
	ret = pthread_setcancelstate(state->oldstate, &oldstate);
	if (ret) {
		ERR("pthread_setcancelstate: ret=%d", ret);
		return -1;
	}
	if (oldstate != PTHREAD_CANCEL_DISABLE) {
		ERR("pthread_setcancelstate: unexpected oldstate");
		return -1;
	}
end:
	return 0;
}


