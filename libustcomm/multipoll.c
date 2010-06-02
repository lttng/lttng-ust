/*
 * multipoll.c
 *
 * Copyright (C) 2010 - Pierre-Marc Fournier (pierre-marc dot fournier at polymtl dot ca)
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

/* Multipoll is a framework to poll on several file descriptors and to call
 * a specific callback depending on the fd that had activity.
 */

#include <poll.h>
#include <stdlib.h>
#include "multipoll.h"
#include "usterr.h"

#define INITIAL_N_AVAIL 16

/* multipoll_init
 *
 * Initialize an mpentries struct, which is initially empty of any fd.
 */

int multipoll_init(struct mpentries *ent)
{
	ent->n_used = 0;
	ent->n_avail = INITIAL_N_AVAIL;

	ent->pollfds = (struct pollfd *) malloc(sizeof(struct pollfd) * INITIAL_N_AVAIL);
	ent->extras = (struct pollfd_extra *) malloc(sizeof(struct pollfd_extra) * INITIAL_N_AVAIL);

	return 0;
}

/* multipoll_destroy: free a struct mpentries
 */

int multipoll_destroy(struct mpentries *ent)
{
	int i;

	for(i=0; i<ent->n_used; i++) {
		if(ent->extras[i].destroy_priv) {
			ent->extras[i].destroy_priv(ent->extras[i].priv);
		}
	}

	free(ent->pollfds);
	free(ent->extras);

	return 0;
}

/* multipoll_add
 *
 * Add a file descriptor to be waited on in a struct mpentries.
 *
 * @ent: the struct mpentries to add an fd to
 * @fd: the fd to wait on
 * @events: a mask of the types of events to wait on, see the poll(2) man page
 * @func: the callback function to be called if there is activity on the fd
 * @priv: the private pointer to pass to func
 * @destroy_priv: a callback to destroy the priv pointer when the mpentries
                  is destroyed; may be NULL
 */

int multipoll_add(struct mpentries *ent, int fd, short events, int (*func)(void *priv, int fd, short events), void *priv, int (*destroy_priv)(void *))
{
	int cur;

	if(ent->n_used == ent->n_avail) {
		ent->n_avail *= 2;
		ent->pollfds = (struct pollfd *) realloc(ent->pollfds, sizeof(struct pollfd) * ent->n_avail);
		ent->extras = (struct pollfd_extra *) realloc(ent->extras, sizeof(struct pollfd_extra) * ent->n_avail);
	}

	cur = ent->n_used;
	ent->n_used++;

	ent->pollfds[cur].fd = fd;
	ent->pollfds[cur].events = events;
	ent->extras[cur].func = func;
	ent->extras[cur].priv = priv;
	ent->extras[cur].destroy_priv = destroy_priv;

	return 0;
}

/* multipoll_poll: do the actual poll on a struct mpentries
 *
 * File descriptors should have been already added with multipoll_add().
 *
 * A struct mpentries may be reused for multiple multipoll_poll calls.
 *
 * @ent: the struct mpentries to poll on.
 * @timeout: the timeout after which to return if there was no activity.
 */

int multipoll_poll(struct mpentries *ent, int timeout)
{
	int result;
	int i;

	result = poll(ent->pollfds, ent->n_used, timeout);
	if(result == -1) {
		PERROR("poll");
		return -1;
	}

	for(i=0; i<ent->n_used; i++) {
		if(ent->pollfds[i].revents) {
			ent->extras[i].func(ent->extras[i].priv, ent->pollfds[i].fd, ent->pollfds[i].revents);
		}
	}

	return 0;
}
