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
 * The counter clients init/exit symbols are private ABI for
 * liblttng-ust-ctl, which is why they are not hidden.
 */

void lttng_ust_counter_clients_init(void);
void lttng_ust_counter_clients_exit(void);

__attribute__((visibility("hidden")))
void lttng_counter_client_percpu_32_modular_init(void);
__attribute__((visibility("hidden")))
void lttng_counter_client_percpu_32_modular_exit(void);
__attribute__((visibility("hidden")))
void lttng_counter_client_percpu_64_modular_init(void);
__attribute__((visibility("hidden")))
void lttng_counter_client_percpu_64_modular_exit(void);

#endif
