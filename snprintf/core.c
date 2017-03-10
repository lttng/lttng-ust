/*
 * core.c
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <usterr-signal-safe.h>

volatile enum ust_loglevel ust_loglevel;

void init_usterr(void)
{
	char *ust_debug;

	if (ust_loglevel == UST_LOGLEVEL_UNKNOWN) {
		/*
		 * This getenv is not part of lttng_getenv() because it
		 * is required to print ERR() performed during getenv
		 * initialization.
		 */
		ust_debug = getenv("LTTNG_UST_DEBUG");
		if (ust_debug)
			ust_loglevel = UST_LOGLEVEL_DEBUG;
		else
			ust_loglevel = UST_LOGLEVEL_NORMAL;
	}
}
