/*
 * compiler.h
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

#ifndef KCOMPAT_COMPILER_H
#define KCOMPAT_COMPILER_H

# define inline         inline          __attribute__((always_inline))
# define __inline__     __inline__      __attribute__((always_inline))
# define __inline       __inline        __attribute__((always_inline))

#ifndef __always_inline
#define __always_inline inline
#endif

#define __pure                          __attribute__((pure))
#define __aligned(x)                    __attribute__((aligned(x)))
#define __printf(a,b)                   __attribute__((format(printf,a,b)))
#define  noinline                       __attribute__((noinline))
#define __attribute_const__             __attribute__((__const__))
#define __maybe_unused                  __attribute__((unused))

#define notrace __attribute__((no_instrument_function))

#endif /* KCOMPAT_COMPILER_H */
