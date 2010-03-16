#ifndef _KCOMPAT_TYPES
#define _KCOMPAT_TYPES

/*
 * Kernel sourcecode compatibility layer
 *
 * Copyright (C) 2009 Novell Inc.
 *
 * Author: Jan Blunck <jblunck@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 as
 * published by the Free  Software Foundation.
 */

#include <asm/types.h>

#ifdef __KERNEL__
typedef __s8 s8;
typedef __u8 u8;

typedef __s16 s16;
typedef __u16 u16;

typedef __s32 s32;
typedef __u32 u32;

typedef __s64 s64;
typedef __u64 u64;
#endif

#endif /* _KCOMPAT_TYPES */
