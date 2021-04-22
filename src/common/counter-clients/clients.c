/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include "common/counter-clients/clients.h"

void lttng_ust_counter_clients_init(void)
{
	lttng_counter_client_percpu_64_modular_init();
	lttng_counter_client_percpu_32_modular_init();
}

void lttng_ust_counter_clients_exit(void)
{
	lttng_counter_client_percpu_32_modular_exit();
	lttng_counter_client_percpu_64_modular_exit();
}
