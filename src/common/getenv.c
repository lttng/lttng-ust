/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <pthread.h>
#include <urcu/system.h>
#include "common/logging.h"
#include "common/macros.h"
#include "common/getenv.h"

enum lttng_env_secure {
	LTTNG_ENV_SECURE,
	LTTNG_ENV_NOT_SECURE,
};

struct lttng_env {
	const char *key;
	enum lttng_env_secure secure;
	char *value;
};

/* lttng_ust_getenv_init_mutex provides mutual exclusion for initialization. */
static pthread_mutex_t lttng_ust_getenv_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static int lttng_ust_getenv_is_init = 0;

static struct lttng_env lttng_env[] = {
	/*
	 * LTTNG_UST_DEBUG and LTTNG_UST_ABORT_ON_CRITICAL are used directly by
	 * the internal logging, because they need to be already set for ERR()
	 * used in lttng_ust_getenv_init().
	 */
	{ "LTTNG_UST_DEBUG", LTTNG_ENV_NOT_SECURE, NULL, },
	{ "LTTNG_UST_ABORT_ON_CRITICAL", LTTNG_ENV_NOT_SECURE, NULL, },

	/* Env. var. which can be used in setuid/setgid executables. */
	{ "LTTNG_UST_WITHOUT_BADDR_STATEDUMP", LTTNG_ENV_NOT_SECURE, NULL, },
	{ "LTTNG_UST_REGISTER_TIMEOUT", LTTNG_ENV_NOT_SECURE, NULL, },
	{ "LTTNG_UST_MAP_POPULATE_POLICY", LTTNG_ENV_NOT_SECURE, NULL, },

	/* Env. var. which are not fetched in setuid/setgid executables. */
	{ "LTTNG_UST_CLOCK_PLUGIN", LTTNG_ENV_SECURE, NULL, },
	{ "LTTNG_UST_GETCPU_PLUGIN", LTTNG_ENV_SECURE, NULL, },
	{ "LTTNG_UST_ALLOW_BLOCKING", LTTNG_ENV_SECURE, NULL, },
	{ "HOME", LTTNG_ENV_SECURE, NULL, },
	{ "LTTNG_HOME", LTTNG_ENV_SECURE, NULL, },
	{ "LTTNG_UST_APP_PATH", LTTNG_ENV_SECURE, NULL, },
};

static
int lttng_is_setuid_setgid(void)
{
	return geteuid() != getuid() || getegid() != getgid();
}

/*
 * Wrapper over getenv that will only return the values of whitelisted
 * environment variables when the current process is setuid and/or setgid.
 */
char *lttng_ust_getenv(const char *name)
{
	size_t i;
	struct lttng_env *e;
	bool found = false;

	/*
	 * Perform lazy initialization of lttng_ust_getenv for early use
	 * by library constructors.
	 */
	lttng_ust_getenv_init();

	for (i = 0; i < LTTNG_ARRAY_SIZE(lttng_env); i++) {
		e = &lttng_env[i];

		if (strcmp(e->key, name) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		return NULL;
	}
	return e->value;
}

void lttng_ust_getenv_init(void)
{
	size_t i;

	/*
	 * Return early if the init has already completed.
	 */
	if (CMM_LOAD_SHARED(lttng_ust_getenv_is_init)) {
		/*
		 * Load lttng_ust_getenv_is_init before reading environment cache.
		 */
		cmm_smp_rmb();
		return;
	}

	pthread_mutex_lock(&lttng_ust_getenv_init_mutex);

	/*
	 * Check again if the init has completed in another thread now that we
	 * have acquired the mutex.
	 */
	if (lttng_ust_getenv_is_init)
		goto end_init;

	for (i = 0; i < LTTNG_ARRAY_SIZE(lttng_env); i++) {
		struct lttng_env *e = &lttng_env[i];

		if (e->secure == LTTNG_ENV_SECURE && lttng_is_setuid_setgid()) {
			ERR("Getting environment variable '%s' from setuid/setgid binary refused for security reasons.",
				e->key);
			continue;
		}
		e->value = getenv(e->key);
	}

	/*
	 * Store environment cache before setting lttng_ust_getenv_is_init to 1.
	 */
	cmm_smp_wmb();
	CMM_STORE_SHARED(lttng_ust_getenv_is_init, 1);
end_init:
	pthread_mutex_unlock(&lttng_ust_getenv_init_mutex);
}
