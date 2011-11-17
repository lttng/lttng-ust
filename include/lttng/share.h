#ifndef _LTTNG_SHARE_H
#define _LTTNG_SHARE_H

/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

ssize_t patient_write(int fd, const void *buf, size_t count);
ssize_t patient_send(int fd, const void *buf, size_t count, int flags);

#endif /* _LTTNG_SHARE_H */
