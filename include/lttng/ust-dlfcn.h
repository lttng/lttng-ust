#ifndef _LTTNG_UST_DLFCN_H
#define _LTTNG_UST_DLFCN_H

/*
 * lttng/ust-dlfcn.h
 *
 * Copyright 2014 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * dlfcn.h compatibility layer.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef _DLFCN_H
#error "Please include lttng/ust-dlfcn.h before dlfcn.h."
#endif /* _DLFCN_H */

#ifdef __GLIBC__
/*
 * glibc declares dlsym() and dlerror() with __attribute__((leaf)) (see
 * THROW annotation). Unfortunately, this is not in sync with reality,
 * as those functions call the memory allocator. Work-around this glibc
 * bug by declaring our own symbols.
 *
 * There has been a similar issue for dlopen() and dlclose(), as
 * constructors and destructors are called from these functions, so they
 * are clearly non-leaf. Work-around the issue for those too for older
 * glibc where these have not been fixed.
 */
#define dlopen glibc_dlopen_proto_lies_about_leafness
#define dlclose glibc_dlclose_proto_lies_about_leafness
#define dlsym glibc_dlsym_proto_lies_about_leafness
#define dlerror glibc_dlerror_proto_lies_about_leafness
#define dlmopen glibc_dlmopen_proto_lies_about_leafness
#define dlvsym glibc_dlvsym_proto_lies_about_leafness
#include <dlfcn.h>
#undef dlvsym
#undef dlmopen
#undef dlerror
#undef dlsym
#undef dlclose
#undef dlopen

extern void *dlopen(__const char *__file, int __mode);
extern int dlclose(void *__handle) __nonnull ((1));
extern void *dlsym(void *__restrict __handle,
		__const char *__restrict __name) __nonnull ((2));
extern char *dlerror(void);
#ifdef __USE_GNU
extern void *dlmopen(Lmid_t __nsid, const char *__file, int __mode);
extern void *dlvsym(void *__restrict __handle,
		__const char *__restrict __name,
		__const char *__restrict __version);
#endif
#else
#include <dlfcn.h>
#endif /* __GLIBC__ */

#endif /* _LTTNG_UST_DLFCN_H */
