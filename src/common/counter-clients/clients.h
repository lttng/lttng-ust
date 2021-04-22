/*
 * SPDX-License-Identifier: (GPL-2.0-only or LGPL-2.1-only)
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib counter client.
 */

#ifndef _UST_COMMON_COUNTER_CLIENTS_CLIENTS_H
#define _UST_COMMON_COUNTER_CLIENTS_CLIENTS_H

void lttng_ust_counter_clients_init(void)
	__attribute__((visibility("hidden")));

void lttng_ust_counter_clients_exit(void)
	__attribute__((visibility("hidden")));

void lttng_counter_client_percpu_32_modular_init(void)
	__attribute__((visibility("hidden")));

void lttng_counter_client_percpu_32_modular_exit(void)
	__attribute__((visibility("hidden")));

void lttng_counter_client_percpu_64_modular_init(void)
	__attribute__((visibility("hidden")));

void lttng_counter_client_percpu_64_modular_exit(void)
	__attribute__((visibility("hidden")));

#endif /* _UST_COMMON_COUNTER_CLIENTS_CLIENTS_H */
