/*
 * multipoll.h
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

#ifndef UST_MULTIPOLL_H
#define UST_MULTIPOLL_H

struct pollfd_extra {
	int (*func)(void *priv, int fd, short events);
	void *priv;

	int (*destroy_priv)(void *priv);
};

struct mpentries {
	struct pollfd *pollfds;
	struct pollfd_extra *extras;

	int n_used;
	int n_avail;
};

extern int multipoll_init(struct mpentries *ent);
extern int multipoll_add(struct mpentries *ent, int fd, short events, int (*func)(void *priv, int fd, short events), void *priv, int (*destroy_priv)(void *));
extern int multipoll_destroy(struct mpentries *ent);
extern int multipoll_poll(struct mpentries *ent, int timeout);

#endif /* UST_MULTIPOLL_H */
