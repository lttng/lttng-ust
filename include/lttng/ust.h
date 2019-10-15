#ifndef _LTTNG_UST_H
#define _LTTNG_UST_H

/*
 * Copyright (c) 2011-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void ust_before_fork(sigset_t *save_sigset);
extern void ust_after_fork_parent(sigset_t *restore_sigset);
extern void ust_after_fork_child(sigset_t *restore_sigset);
extern void ust_after_setns(void);
extern void ust_after_unshare(void);
extern void ust_after_setuid(void);
extern void ust_after_setgid(void);
extern void ust_after_seteuid(void);
extern void ust_after_setegid(void);
extern void ust_after_setreuid(void);
extern void ust_after_setregid(void);
extern void ust_after_setresuid(void);
extern void ust_after_setresgid(void);

#ifdef __cplusplus 
}
#endif

#endif /* _LTTNG_UST_H */
