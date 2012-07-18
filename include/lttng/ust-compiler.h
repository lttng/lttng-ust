#ifndef _LTTNG_UST_COMPILER_H
#define _LTTNG_UST_COMPILER_H

/*
 * Copyright 2011-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *                       Paul Woegerer <paul_woegerer@mentor.com>
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

#define lttng_ust_notrace __attribute__((no_instrument_function))

#endif /* _LTTNG_UST_COMPILER_H */
