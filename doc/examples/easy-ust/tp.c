/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

/*
 * Defining macro creates the code objects of the traceprobes, only do
 * it once per file
 */
#define TRACEPOINT_CREATE_PROBES
/*
 * The header containing our LTTNG_UST_TRACEPOINT_EVENTs.
 */
#include "sample_component_provider.h"
