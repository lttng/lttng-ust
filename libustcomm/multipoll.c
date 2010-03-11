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

#include <poll.h>
#include <stdlib.h>
#include "multipoll.h"
#include "usterr.h"

#define INITIAL_N_AVAIL 16

int multipoll_init(struct mpentries *ent)
{
	ent->n_used = 0;
	ent->n_avail = INITIAL_N_AVAIL;

	ent->pollfds = (struct pollfd *) malloc(sizeof(struct pollfd) * 16);
	ent->extras = (struct pollfd_extra *) malloc(sizeof(struct pollfd_extra) * 16);

	return 0;
}

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
