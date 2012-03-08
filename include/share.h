#ifndef _LTTNG_SHARE_H
#define _LTTNG_SHARE_H

/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 */

#include <stdlib.h>

ssize_t patient_write(int fd, const void *buf, size_t count);
ssize_t patient_send(int fd, const void *buf, size_t count, int flags);

#endif /* _LTTNG_SHARE_H */
