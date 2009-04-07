#include <assert.h>

#include "tracer.h"
#include "ustd.h"
#include "localerr.h"

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

	long first_subbuf = consumed_offset / buf->subbuf_size;
	long last_subbuf = write_offset / buf->subbuf_size;

	if(last_subbuf - first_subbuf > buf->n_subbufs) {
		DBG("an overflow has occurred, nothing can be recovered");
		return;
	}

	for(i_subbuf=first_subbuf; ; i_subbuf++, i_subbuf %= buf->n_subbufs) {
		void *tmp;
		long commit_seq = local_read(&ltt_buf->commit_seq[i_subbuf]);

		unsigned long valid_length = buf->subbuf_size;
		long n_subbufs_order = get_count_order(buf->n_subbufs);
		long commit_seq_mask = (~0UL >> n_subbufs_order);

		if((commit_seq & commit_seq_mask) == 0)
			break;

		/* check if subbuf was fully written */
		if (!((commit_seq - buf->subbuf_size) & commit_seq_mask)
		    - (USTD_BUFFER_TRUNC(consumed_offset, buf) >> n_subbufs_order)
		    != 0) {
			struct ltt_subbuffer_header *header = (struct ltt_subbuffer_header *)((char *)buf->mem)+i_subbuf*buf->subbuf_size;
			valid_length = (unsigned long)buf->subbuf_size - header->lost_size;
		}
		else {
			struct ltt_subbuffer_header *header = (struct ltt_subbuffer_header *)((char *)buf->mem)+i_subbuf*buf->subbuf_size;

			valid_length = commit_seq;
			header->lost_size = buf->subbuf_size-valid_length;
			assert(i_subbuf == last_subbuf);
		}

		patient_write(buf->file_fd, buf->mem + i_subbuf * buf->subbuf_size, valid_length);

		/* pad with empty bytes */
		tmp = malloc(buf->subbuf_size-valid_length);
		memset(tmp, 0, buf->subbuf_size-valid_length);
		patient_write(buf->file_fd, tmp, buf->subbuf_size-valid_length);
		free(tmp);

		if(i_subbuf == last_subbuf)
			break;
	}
}

