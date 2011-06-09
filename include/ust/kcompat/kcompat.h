/*
 * kcompat.h
 *
 * Copyright (C) 2009 - Pierre-Marc Fournier (pierre-marc dot fournier at polymtl dot ca)
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

#ifndef KCOMPAT_H
#define KCOMPAT_H

#define __KERNEL__
#define _LOOSE_KERNEL_NAMES

#ifndef CONFIG_SMP
#define CONFIG_SMP 1 /* Needed for urcu, verify it's ok to remove it. */
#endif

#include <limits.h>
#include <bits/wordsize.h>
#if __WORDSIZE == 32
#define LIBKCOMPAT_X86_32
#elif __WORDSIZE == 64
#define LIBKCOMPAT_X86_64
#else
#error "Unsupported"
#endif

#ifdef LIBKCOMPAT_X86_32
#define CONFIG_X86_32
#define CONFIG_32BIT
#endif

#ifdef LIBKCOMPAT_X86_64
#define CONFIG_X86_64
#define CONFIG_64BIT
#endif

/* Standard libs */
#include <stdint.h>
#include <stddef.h>

/* Taken from userspace-rcu */
#include <urcu/arch.h>

/* Kernel libs */
#include <ust/kcompat/compiler.h>
#include <ust/kcompat/types.h>
#include <ust/kcompat/jhash.h>

#endif /* KCOMPAT_H */
