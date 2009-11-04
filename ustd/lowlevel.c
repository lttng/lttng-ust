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

#include <assert.h>

#include <ust/tracer.h>
#include "ustd.h"
#include "usterr.h"

/* This truncates to an offset in the buffer. */
#define USTD_BUFFER_TRUNC(offset, bufinfo) \
	((offset) & (~(((bufinfo)->subbuf_size*(bufinfo)->n_subbufs)-1)))

void finish_consuming_dead_subbuffer(struct buffer_info *buf)
{
	struct ltt_channel_buf_struct *ltt_buf = buf->bufstruct_mem;

	long write_offset = local_read(&ltt_buf->offset);
	long consumed_offset = atomic_long_read(&ltt_buf->consumed);

	long i_subbuf;

	DBG("processing died buffer");
	DBG("consumed offset is %ld", consumed_offset);
	DBG("write offset is %ld", write_offset);

	/* First subbuf that we need to consume now. It is not modulo'd.
	 * Consumed_offset is the next byte to consume.  */
	long first_subbuf = consumed_offset / buf->subbuf_size;
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
	for(i_subbuf=first_subbuf; ; i_subbuf++, i_subbuf %= buf->n_subbufs) {
		void *tmp;
		/* commit_seq is the offset in the buffer of the end of the last sequential commit.
		 * Bytes beyond this limit cannot be recovered. This is a free-running counter. */
		long commit_seq = local_read(&ltt_buf->commit_seq[i_subbuf]);

		unsigned long valid_length = buf->subbuf_size;
		long n_subbufs_order = get_count_order(buf->n_subbufs);
		long commit_seq_mask = (~0UL >> n_subbufs_order);

		struct ltt_subbuffer_header *header = (struct ltt_subbuffer_header *)((char *)buf->mem+i_subbuf*buf->subbuf_size);

		if((commit_seq & commit_seq_mask) == 0) {
			/* There is nothing to do. */
			/* FIXME: is this needed? */
			break;
		}

		/* Check if subbuf was fully written. This is from Mathieu's algorithm/paper. */
		if (((commit_seq - buf->subbuf_size) & commit_seq_mask)
		    - (USTD_BUFFER_TRUNC(consumed_offset, buf) >> n_subbufs_order)
		    == 0) {
			/* If it was, we only check the lost_size. This is the lost padding at the end of
 			 * the subbuffer. */
			valid_length = (unsigned long)buf->subbuf_size - header->lost_size;
		}
		else {
			/* If the subbuffer was not fully written, then we don't check lost_size because
			 * it hasn't been written yet. Instead we check commit_seq and use it to choose
			 * a value for lost_size. The viewer will need this value when parsing.
			 */

			valid_length = commit_seq & (buf->subbuf_size-1);
			header->lost_size = buf->subbuf_size-valid_length;
			assert(i_subbuf == (last_subbuf % buf->n_subbufs));
		}


		patient_write(buf->file_fd, buf->mem + i_subbuf * buf->subbuf_size, valid_length);

		/* pad with empty bytes */
		tmp = malloc(buf->subbuf_size-valid_length);
		memset(tmp, 0, buf->subbuf_size-valid_length);
		patient_write(buf->file_fd, tmp, buf->subbuf_size-valid_length);
		free(tmp);

		if(i_subbuf == last_subbuf % buf->n_subbufs)
			break;
	}
}

