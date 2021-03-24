/*
 * SPDX-License-Identifier: (GPL-2.0-only or LGPL-2.1-only)
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib counter client.
 */

#ifndef _LTTNG_UST_COUNTER_CLIENT_H
#define _LTTNG_UST_COUNTER_CLIENT_H

/*
 * These symbol are part of the private ABI between liblttng-ust and
 * liblttng-ust-ctl.
 */
void lttng_counter_client_percpu_32_modular_init(void);
void lttng_counter_client_percpu_32_modular_exit(void);
void lttng_counter_client_percpu_64_modular_init(void);
void lttng_counter_client_percpu_64_modular_exit(void);

#endif
