#ifndef _LTTNG_RING_BUFFER_ABI_H
#define _LTTNG_RING_BUFFER_ABI_H

/*
 * lttng/ringbuffer-abi.h
 *
 * (C) Copyright 2005-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Wait-free ring buffer ABI.
 *
 * Author:
 *	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _UST_CMD(minor)				(minor)
#define _UST_CMDR(minor, type)			(minor)
#define _UST_CMDW(minor, type)			(minor)

/*
 * Use RING_BUFFER_GET_NEXT_SUBBUF / RING_BUFFER_PUT_NEXT_SUBBUF to read and
 * consume sub-buffers sequentially.
 *
 * Reading sub-buffers without consuming them can be performed with:
 *
 * RING_BUFFER_SNAPSHOT
 * RING_BUFFER_SNAPSHOT_GET_CONSUMED
 * RING_BUFFER_SNAPSHOT_GET_PRODUCED
 *
 * to get the offset range to consume, and then by passing each sub-buffer
 * offset to RING_BUFFER_GET_SUBBUF, read the sub-buffer, and then release it
 * with RING_BUFFER_PUT_SUBBUF.
 *
 * Note that the "snapshot" API can be used to read the sub-buffer in reverse
 * order, which is useful for flight recorder snapshots.
 */

/* Get a snapshot of the current ring buffer producer and consumer positions */
#define RING_BUFFER_SNAPSHOT			_UST_CMD(0x00)
/* Get the consumer position (iteration start) */
#define RING_BUFFER_SNAPSHOT_GET_CONSUMED	_UST_CMDR(0x01, unsigned long)
/* Get the producer position (iteration end) */
#define RING_BUFFER_SNAPSHOT_GET_PRODUCED	_UST_CMDR(0x02, unsigned long)
/* Get exclusive read access to the specified sub-buffer position */
#define RING_BUFFER_GET_SUBBUF			_UST_CMDW(0x03, unsigned long)
/* Release exclusive sub-buffer access */
#define RING_BUFFER_PUT_SUBBUF			_UST_CMD(0x04)

/* Get exclusive read access to the next sub-buffer that can be read. */
#define RING_BUFFER_GET_NEXT_SUBBUF		_UST_CMD(0x05)
/* Release exclusive sub-buffer access, move consumer forward. */
#define RING_BUFFER_PUT_NEXT_SUBBUF		_UST_CMD(0x06)
/* returns the size of the current sub-buffer, without padding (for mmap). */
#define RING_BUFFER_GET_SUBBUF_SIZE		_UST_CMDR(0x07, unsigned long)
/* returns the size of the current sub-buffer, with padding (for splice). */
#define RING_BUFFER_GET_PADDED_SUBBUF_SIZE	_UST_CMDR(0x08, unsigned long)
/* returns the maximum size for sub-buffers. */
#define RING_BUFFER_GET_MAX_SUBBUF_SIZE		_UST_CMDR(0x09, unsigned long)
/* returns the length to mmap. */
#define RING_BUFFER_GET_MMAP_LEN		_UST_CMDR(0x0A, unsigned long)
/* returns the offset of the subbuffer belonging to the mmap reader. */
#define RING_BUFFER_GET_MMAP_READ_OFFSET	_UST_CMDR(0x0B, unsigned long)
/* flush the current sub-buffer */
#define RING_BUFFER_FLUSH			_UST_CMD(0x0C)

#endif /* _LTTNG_RING_BUFFER_ABI_H */
