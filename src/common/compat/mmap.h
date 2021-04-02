/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 */

#ifndef _UST_COMMON_COMPAT_MMAP_H
#define _UST_COMMON_COMPAT_MMAP_H

#include <sys/mman.h>

#if defined(__linux__) && defined(MAP_POPULATE)
# define LTTNG_MAP_POPULATE MAP_POPULATE
#else
# define LTTNG_MAP_POPULATE 0
#endif /* __linux__ && MAP_POPULATE */

#endif /* _UST_COMMON_COMPAT_MMAP_H */
