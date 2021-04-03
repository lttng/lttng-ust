/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 */

#ifndef _UST_COMMON_COMPAT_ERRNO_H
#define _UST_COMMON_COMPAT_ERRNO_H

#include <errno.h>

#ifndef ENODATA
#define ENODATA	ENOMSG
#endif

#endif /* _UST_COMMON_COMPAT_ERRNO_H */
