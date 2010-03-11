/* Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

#ifndef UST_TRACECTL_H
#define UST_TRACECTL_H

typedef struct ust_fork_info {
	sigset_t orig_sigs;
} ust_fork_info_t;

extern void ust_potential_exec(void);

extern void ust_before_fork(ust_fork_info_t *fork_info);
extern void ust_after_fork_parent(ust_fork_info_t *fork_info);
extern void ust_after_fork_child(ust_fork_info_t *fork_info);

#endif /* UST_TRACECTL_H */
