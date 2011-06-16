/*
 * lowlevel libustd header file
 *
 * Copyright 2005-2010 -
 * 		 Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 * Copyright 2010-
 *		 Oumarou Dicko <oumarou.dicko@polymtl.ca>
 *		 Michael Sills-Lavoie <michael.sills-lavoie@polymtl.ca>
 *		 Alexis Halle <alexis.halle@polymtl.ca>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LOWLEVEL_H
#define LOWLEVEL_H

#include "ust/ustconsumer.h"

void finish_consuming_dead_subbuffer(struct ustconsumer_callbacks *callbacks, struct buffer_info *buf);
size_t subbuffer_data_size(void *subbuf);

#endif /* LOWLEVEL_H */

