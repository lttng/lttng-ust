/* SPDX-License-Identifier: (GPL-2.0-only or LGPL-2.1-only)
 *
 * lttng-counter-client-percpu-64-modular.c
 *
 * LTTng lib counter client. Per-cpu 64-bit counters in modular
 * arithmetic.
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include "common/counter-clients/clients.h"
#include "common/counter/counter-api.h"
#include "common/counter/counter.h"
#include "common/events.h"
#include "common/tracer.h"

static const struct lib_counter_config client_config = {
	.alloc = COUNTER_ALLOC_PER_CPU,
	.sync = COUNTER_SYNC_PER_CPU,
	.arithmetic = COUNTER_ARITHMETIC_MODULAR,
	.counter_size = COUNTER_SIZE_64_BIT,
};

static struct lttng_ust_channel_counter *counter_create(size_t nr_dimensions,
					  const struct lttng_counter_dimension *dimensions,
					  int64_t global_sum_step,
					  int channel_counter_fd,
					  int nr_counter_cpu_fds,
					  const int *counter_cpu_fds,
					  bool is_daemon)
{
	size_t max_nr_elem[LTTNG_COUNTER_DIMENSION_MAX], i;
	struct lttng_ust_channel_counter *lttng_chan_counter;
	struct lib_counter *counter;

	if (nr_dimensions > LTTNG_COUNTER_DIMENSION_MAX)
		return NULL;
	for (i = 0; i < nr_dimensions; i++) {
		if (dimensions[i].has_underflow || dimensions[i].has_overflow)
			return NULL;
		max_nr_elem[i] = dimensions[i].size;
	}
	lttng_chan_counter = lttng_ust_alloc_channel_counter();
	if (!lttng_chan_counter)
		return NULL;
	counter = lttng_counter_create(&client_config, nr_dimensions, max_nr_elem,
				    global_sum_step, channel_counter_fd, nr_counter_cpu_fds,
				    counter_cpu_fds, is_daemon);
	if (!counter)
		goto error;
	lttng_chan_counter->priv->counter = counter;
	for (i = 0; i < nr_dimensions; i++)
		lttng_chan_counter->priv->dimension_key_types[i] = dimensions[i].key_type;
	return lttng_chan_counter;

error:
	lttng_ust_free_channel_common(lttng_chan_counter->parent);
	return NULL;
}

static void counter_destroy(struct lttng_ust_channel_counter *counter)
{
	lttng_counter_destroy(counter->priv->counter);
	lttng_ust_free_channel_common(counter->parent);
}

static int counter_add(struct lttng_ust_channel_counter *counter,
		       const size_t *dimension_indexes, int64_t v)
{
	return lttng_counter_add(&client_config, counter->priv->counter, dimension_indexes, v);
}

static int counter_hit(struct lttng_ust_event_counter *event_counter,
		const char *stack_data __attribute__((unused)),
		struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		struct lttng_ust_event_counter_ctx *event_counter_ctx __attribute__((unused)))
{
	struct lttng_ust_channel_counter *counter = event_counter->chan;

	switch (event_counter->priv->action) {
	case LTTNG_EVENT_COUNTER_ACTION_INCREMENT:
	{
		size_t index = event_counter->priv->parent.id;
		return counter_add(counter, &index, 1);
	}
	default:
		return -ENOSYS;
	}
}

static int counter_read(struct lttng_ust_channel_counter *counter, const size_t *dimension_indexes, int cpu,
			int64_t *value, bool *overflow, bool *underflow)
{
	return lttng_counter_read(&client_config, counter->priv->counter, dimension_indexes, cpu, value,
				  overflow, underflow);
}

static int counter_aggregate(struct lttng_ust_channel_counter *counter, const size_t *dimension_indexes,
			     int64_t *value, bool *overflow, bool *underflow)
{
	return lttng_counter_aggregate(&client_config, counter->priv->counter, dimension_indexes, value,
				       overflow, underflow);
}

static int counter_clear(struct lttng_ust_channel_counter *counter, const size_t *dimension_indexes)
{
	return lttng_counter_clear(&client_config, counter->priv->counter, dimension_indexes);
}

static struct lttng_counter_transport lttng_counter_transport = {
	.name = "counter-per-cpu-64-modular",
	.ops = {
		.struct_size = sizeof(struct lttng_ust_channel_counter_ops),
		.priv = LTTNG_UST_COMPOUND_LITERAL(struct lttng_ust_channel_counter_ops_private, {
			.pub = &lttng_counter_transport.ops,
			.counter_create = counter_create,
			.counter_destroy = counter_destroy,
			.counter_add = counter_add,
			.counter_read = counter_read,
			.counter_aggregate = counter_aggregate,
			.counter_clear = counter_clear,
		}),
		.counter_hit = counter_hit,
	},
	.client_config = &client_config,
};

void lttng_counter_client_percpu_64_modular_init(void)
{
	lttng_counter_transport_register(&lttng_counter_transport);
}

void lttng_counter_client_percpu_64_modular_exit(void)
{
	lttng_counter_transport_unregister(&lttng_counter_transport);
}
