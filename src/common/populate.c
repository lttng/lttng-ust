/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include "common/getenv.h"
#include "common/logging.h"
#include "common/populate.h"

enum populate_policy {
	POPULATE_UNSET,

	POPULATE_NONE,
	POPULATE_CPU_POSSIBLE,

	POPULATE_UNKNOWN,
};

static enum populate_policy map_populate_policy = POPULATE_UNSET;

static void init_map_populate_policy(void)
{
	const char *populate_env_str;

	if (map_populate_policy != POPULATE_UNSET)
		return;

	populate_env_str = lttng_ust_getenv("LTTNG_UST_MAP_POPULATE_POLICY");
	if (!populate_env_str) {
		map_populate_policy = POPULATE_NONE;
		return;
	}
	if (!strcmp(populate_env_str, "none")) {
		map_populate_policy = POPULATE_NONE;
	} else if (!strcmp(populate_env_str, "cpu_possible")) {
		map_populate_policy = POPULATE_CPU_POSSIBLE;
	} else {
		/*
		 * populate_env_str is an untrusted environment variable
		 * input (can be provided to setuid/setgid binaries), so
		 * don't even try to print it.
		 */
		WARN("Unknown policy for LTTNG_UST_MAP_POPULATE_POLICY environment variable.");
		map_populate_policy = POPULATE_UNKNOWN;
	}
}

/*
 * Return the shared page populate policy for global pages. Returns true
 * if shared memory pages should be pre-populated, false otherwise.
 */
bool lttng_ust_map_populate_is_enabled(void)
{
	init_map_populate_policy();

	switch (map_populate_policy) {
	case POPULATE_UNKNOWN:	/* Fall-through */
	case POPULATE_NONE:
		return false;
	case POPULATE_CPU_POSSIBLE:
		return true;
	default:
		abort();
	}
	return false;
}

/*
 * Return the shared page populate policy based on the @cpu number
 * provided as input. Returns true if shared memory pages should be
 * pre-populated, false otherwise.
 *
 * The @cpu argument is currently unused except for negative value
 * validation. It is present to eventually match cpu affinity or cpu
 * online masks if those features are added in the future.
 */
bool lttng_ust_map_populate_cpu_is_enabled(int cpu)
{
	/* Reject invalid cpu number. */
	if (cpu < 0)
		return false;

	return lttng_ust_map_populate_is_enabled();
}
