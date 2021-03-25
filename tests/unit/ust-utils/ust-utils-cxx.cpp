/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <lttng/ust-utils.h>

extern "C" {
	/*
	 * Share test code with C test
	 */
	#include "./ust-utils-common.h"
}
