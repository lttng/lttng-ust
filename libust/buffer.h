#ifndef UST_BUFFER_H
#define UST_BUFFER_H

/* Buffer offset macros */

/*
 * BUFFER_TRUNC zeroes the subbuffer offset and the subbuffer number parts of
 * the offset, which leaves only the buffer number.
 */
#define BUFFER_TRUNC(offset, chan) \
	((offset) & (~((chan)->alloc_size-1)))
#define BUFFER_OFFSET(offset, chan) ((offset) & ((chan)->alloc_size - 1))
#define SUBBUF_OFFSET(offset, chan) ((offset) & ((chan)->subbuf_size - 1))
#define SUBBUF_ALIGN(offset, chan) \
	(((offset) + (chan)->subbuf_size) & (~((chan)->subbuf_size - 1)))
#define SUBBUF_TRUNC(offset, chan) \
	((offset) & (~((chan)->subbuf_size - 1)))
#define SUBBUF_INDEX(offset, chan) \
	(BUFFER_OFFSET((offset), chan) >> (chan)->subbuf_size_order)


#endif /* UST_BUFFER_H */
