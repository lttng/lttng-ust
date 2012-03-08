#ifndef _LTTNG_UST_LIB_RINGBUFFER_TLS_FIXUP_H
#define _LTTNG_UST_LIB_RINGBUFFER_TLS_FIXUP_H

/*
 * libringbuffer/tlsfixup.h
 *
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

void lttng_fixup_ringbuffer_tls(void);

#endif /* _LTTNG_UST_LIB_RINGBUFFER_TLS_FIXUP_H */
