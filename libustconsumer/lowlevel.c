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

#include <stdlib.h>
#include <assert.h>
#include <byteswap.h>

#include "ust/ustconsumer.h"
#include "buffers.h"
#include "tracer.h"
#include "usterr.h"

/* This truncates to an offset in the buffer. */
#define USTD_BUFFER_TRUNC(offset, bufinfo) \
	((offset) & (~(((bufinfo)->subbuf_size*(bufinfo)->n_subbufs)-1)))

#define LTT_MAGIC_NUMBER 0x00D6B7ED
#define LTT_REV_MAGIC_NUMBER 0xEDB7D600


static void ltt_relay_print_subbuffer_errors(
		struct buffer_info *buf,
		long cons_off, int cpu)
{
	struct ust_buffer *ust_buf = buf->bufstruct_mem;
	long cons_idx, commit_count, commit_count_mask, write_offset;

	cons_idx = SUBBUF_INDEX(cons_off, buf);
	commit_count = uatomic_read(&ust_buf->commit_seq[cons_idx]);
	commit_count_mask = (~0UL >> get_count_order(buf->n_subbufs));

	/*
	 * No need to order commit_count and write_offset reads because we
	 * execute after trace is stopped when there are no readers left.
	 */
	write_offset = uatomic_read(&ust_buf->offset);
	WARN( "LTT : unread channel %s offset is %ld "
			"and cons_off : %ld (cpu %d)\n",
			buf->channel, write_offset, cons_off, cpu);
	/* Check each sub-buffer for non filled commit count */
	if (((commit_count - buf->subbuf_size) & commit_count_mask)
			- (BUFFER_TRUNC(cons_off, buf) >> get_count_order(buf->n_subbufs)) != 0) {
		ERR("LTT : %s : subbuffer %lu has non filled "
				"commit count [seq] [%lu].\n",
				buf->channel, cons_idx, commit_count);
	}
	ERR("LTT : %s : commit count : %lu, subbuf size %d\n",
			buf->channel, commit_count,
			buf->subbuf_size);
}

static void ltt_relay_print_errors(struct buffer_info *buf, int cpu)
{
	struct ust_buffer *ust_buf = buf->bufstruct_mem;
	long cons_off;

	for (cons_off = uatomic_read(&ust_buf->consumed);
			(SUBBUF_TRUNC(uatomic_read(&ust_buf->offset), buf)
				- cons_off) > 0;
			cons_off = SUBBUF_ALIGN(cons_off, buf))
		ltt_relay_print_subbuffer_errors(buf, cons_off, cpu);
}

static void ltt_relay_print_buffer_errors(struct buffer_info *buf, int cpu)
{
	struct ust_buffer *ust_buf = buf->bufstruct_mem;

	if (uatomic_read(&ust_buf->events_lost))
		ERR("channel %s: %ld events lost (cpu %d)",
				buf->channel,
				uatomic_read(&ust_buf->events_lost), cpu);
	if (uatomic_read(&ust_buf->corrupted_subbuffers))
		ERR("channel %s : %ld corrupted subbuffers (cpu %d)",
				buf->channel,
				uatomic_read(&ust_buf->corrupted_subbuffers), cpu);

	ltt_relay_print_errors(buf, cpu);
}

/* Returns the size of a subbuffer size. This is the size that
 * will need to be written to disk.
 *
 * @subbuffer: pointer to the beginning of the subbuffer (the
 *             beginning of its header)
 */

size_t subbuffer_data_size(void *subbuf)
{
	struct ltt_subbuffer_header *header = subbuf;
	int reverse;
	u32 data_size;

	if(header->magic_number == LTT_MAGIC_NUMBER) {
		reverse = 0;
	}
	else if(header->magic_number == LTT_REV_MAGIC_NUMBER) {
		reverse = 1;
	}
	else {
		return -1;
	}

	data_size = header->sb_size;
	if(reverse)
		data_size = bswap_32(data_size);

	return data_size;
}


void finish_consuming_dead_subbuffer(struct ustconsumer_callbacks *callbacks, struct buffer_info *buf)
{
	struct ust_buffer *ustbuf = buf->bufstruct_mem;
	long write_offset = uatomic_read(&ustbuf->offset);

	long i_subbuf;
	int ret;

	DBG("processing dead buffer (%s)", buf->name);
	DBG("consumed offset is %ld (%s)", uatomic_read(&ustbuf->consumed),
	    buf->name);
	DBG("write offset is %ld (%s)", write_offset, buf->name);

	/* First subbuf that we need to consume now. It is not modulo'd.
	 * Consumed_offset is the next byte to consume.  */
	long first_subbuf = uatomic_read(&ustbuf->consumed) / buf->subbuf_size;
	/* Last subbuf that we need to consume now. It is not modulo'd. 
	 * Write_offset is the next place to write so write_offset-1 is the
	 * last place written. */
	long last_subbuf = (write_offset - 1) / buf->subbuf_size;

	DBG("first_subbuf=%ld", first_subbuf);
	DBG("last_subbuf=%ld", last_subbuf);

	if(last_subbuf - first_subbuf >= buf->n_subbufs) {
		DBG("an overflow has occurred, nothing can be recovered");
		return;
	}

	/* Iterate on subbuffers to recover. */
	for(i_subbuf = first_subbuf % buf->n_subbufs; ; i_subbuf++, i_subbuf %= buf->n_subbufs) {
		/* commit_seq is the offset in the buffer of the end of the last sequential commit.
		 * Bytes beyond this limit cannot be recovered. This is a free-running counter. */
		long commit_seq = uatomic_read(&ustbuf->commit_seq[i_subbuf]);

		unsigned long valid_length = buf->subbuf_size;
		long n_subbufs_order = get_count_order(buf->n_subbufs);
		long commit_seq_mask = (~0UL >> n_subbufs_order);

		struct ltt_subbuffer_header *header = (struct ltt_subbuffer_header *)((char *)buf->mem+i_subbuf*buf->subbuf_size);

		/* Check if subbuf was fully written. This is from Mathieu's algorithm/paper. */
		if (((commit_seq - buf->subbuf_size) & commit_seq_mask)
		    - (USTD_BUFFER_TRUNC(uatomic_read(&ustbuf->consumed), buf) >> n_subbufs_order) == 0
                    && header->data_size != 0xffffffff) {
			assert(header->sb_size != 0xffffffff);
			/*
			 * If it was, we only check the data_size. This is the
			 * amount of valid data at the beginning of the
			 * subbuffer.
			 */
			valid_length = header->data_size;
			DBG("writing full subbuffer (%ld) with valid_length = %ld", i_subbuf, valid_length);
		}
		else {
			/*
			 * If the subbuffer was not fully written, then we don't
			 * check data_size because it hasn't been written yet.
			 * Instead we check commit_seq and use it to choose a
			 * value for data_size. The viewer will need this value
			 * when parsing. Generally, this will happen only for
			 * the last subbuffer. However, if we have threads still
			 * holding reserved slots in the previous subbuffers,
			 * which could happen for other subbuffers prior to the
			 * last one. Note that when data_size is set, the
			 * commit_seq count is still at a value that shows the
			 * amount of valid data to read. It's only _after_
			 * writing data_size that commit_seq is updated to
			 * include the end-of-buffer padding.
			 */
			valid_length = commit_seq & (buf->subbuf_size-1);
			DBG("writing unfull subbuffer (%ld) with valid_length = %ld", i_subbuf, valid_length);
			header->data_size = valid_length;
			header->sb_size = PAGE_ALIGN(valid_length);
		}

		if (callbacks->on_read_partial_subbuffer) {
			ret = callbacks->on_read_partial_subbuffer(callbacks, buf, i_subbuf, valid_length);
			/* Increment the consumed offset */
			if (ret >= 0)
				uatomic_add(&ustbuf->consumed, buf->subbuf_size);
			else
				break;	/* Error happened */
		} else
			uatomic_add(&ustbuf->consumed, buf->subbuf_size);
		if(i_subbuf == last_subbuf % buf->n_subbufs)
			break;
	}

	ltt_relay_print_buffer_errors(buf, buf->channel_cpu);
}

