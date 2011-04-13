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

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <stdio.h>

#include <ust/marker.h>

#if 0
INTERCEPT_PROTOTYPE(void, malloc, size_t size)
INTERCEPT_TRACE("size %d", size)
INTERCEPT_CALL_ARGS(size)
INTERCEPT()

#define INTERCEPT_FUNC(type, name, args...) 						\
__I_FUNC_TYPE(type)									\
__I_FUNC_NAME(name)									\
__I_FUNC_ARGS(args)

#define INTERCEPT_TRACE(fmt, args...)							\
#define __I_TRACE_FMT fmt								\
#define __I_TRACE_ARGS args

#define INTERCEPT_CALL_ARGS(args...)							\
#define __I_CALL_ARGS args

#define INTERCEPT()									\
__I_FUNC_TYPE __I_FUNC_NAME(__I_FUNC_ARGS)						\
{											\
	static __I_FUNC_TYPE (*plibc_ ## __I_FUNC_NAME)(args) = NULL;			\
											\
	if(plibc_ ## __I_FUNC_NAME == NULL) {						\
		plibc_ ## __I_FUNC_NAME = dlsym(RTLD_NEXT, "malloc");			\
		if(plibc_ ## __I_FUNC_NAME == NULL) {					\
			fprintf(stderr, "mallocwrap: unable to find malloc\n");		\
			return NULL;							\
		}									\
	}										\
											\
	ust_marker(ust, __I_FUNC_NAME, __I_TRACE_FMT, __I_TRACE_ARGS);			\
											\
	return plibc_ ## __I_FUNC_NAME (__I_CALL_ARGS);					\
}
#endif

void *malloc(size_t size)
{
	static void *(*plibc_malloc)(size_t size) = NULL;

	void *retval;

	if(plibc_malloc == NULL) {
		plibc_malloc = dlsym(RTLD_NEXT, "malloc");
		if(plibc_malloc == NULL) {
			fprintf(stderr, "mallocwrap: unable to find malloc\n");
			return NULL;
		}
	}

	retval = plibc_malloc(size);

	ust_marker(malloc, "size %d ptr %p", (int)size, retval);

	return retval;
}

void free(void *ptr)
{
	static void *(*plibc_free)(void *ptr) = NULL;

	if(plibc_free == NULL) {
		plibc_free = dlsym(RTLD_NEXT, "free");
		if(plibc_free == NULL) {
			fprintf(stderr, "mallocwrap: unable to find free\n");
			return;
		}
	}

	ust_marker(free, "ptr %p", ptr);

	plibc_free(ptr);
}

MARKER_LIB
