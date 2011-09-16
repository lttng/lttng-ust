/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _UST_H
#define _UST_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ust_fork_info {
	sigset_t orig_sigs;
} ust_fork_info_t;

extern void ust_before_fork(ust_fork_info_t *fork_info);
extern void ust_after_fork_parent(ust_fork_info_t *fork_info);
extern void ust_after_fork_child(ust_fork_info_t *fork_info);

#ifdef __cplusplus 
}
#endif

#endif /* _UST_H */
