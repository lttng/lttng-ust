/*
 * LTTng serializing code.
 *
 * Copyright Mathieu Desnoyers, March 2007.
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
 *
 *
 * See this discussion about weirdness about passing va_list and then va_list to
 * functions. (related to array argument passing). va_list seems to be
 * implemented as an array on x86_64, but not on i386... This is why we pass a
 * va_list * to ltt_vtrace.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define _LGPL_SOURCE
#include <urcu-bp.h>
#include <urcu/rculist.h>

#include <ust/kernelcompat.h>
#include <ust/core.h>
#include "buffers.h"
#include "tracer.h"
//#include "list.h"
#include "usterr.h"
#include "ust_snprintf.h"

enum ltt_type {
	LTT_TYPE_SIGNED_INT,
	LTT_TYPE_UNSIGNED_INT,
	LTT_TYPE_STRING,
	LTT_TYPE_NONE,
};

#define LTT_ATTRIBUTE_NETWORK_BYTE_ORDER (1<<1)

/*
 * Inspired from vsnprintf
 *
 * The serialization format string supports the basic printf format strings.
 * In addition, it defines new formats that can be used to serialize more
 * complex/non portable data structures.
 *
 * Typical use:
 *
 * field_name %ctype
 * field_name #tracetype %ctype
 * field_name #tracetype %ctype1 %ctype2 ...
 *
 * A conversion is performed between format string types supported by GCC and
 * the trace type requested. GCC type is used to perform type checking on format
 * strings. Trace type is used to specify the exact binary representation
 * in the trace. A mapping is done between one or more GCC types to one trace
 * type. Sign extension, if required by the conversion, is performed following
 * the trace type.
 *
 * If a gcc format is not declared with a trace format, the gcc format is
 * also used as binary representation in the trace.
 *
 * Strings are supported with %s.
 * A single tracetype (sequence) can take multiple c types as parameter.
 *
 * c types:
 *
 * see printf(3).
 *
 * Note: to write a uint32_t in a trace, the following expression is recommended
 * si it can be portable:
 *
 * ("#4u%lu", (unsigned long)var)
 *
 * trace types:
 *
 * Serialization specific formats :
 *
 * Fixed size integers
 * #1u     writes uint8_t
 * #2u     writes uint16_t
 * #4u     writes uint32_t
 * #8u     writes uint64_t
 * #1d     writes int8_t
 * #2d     writes int16_t
 * #4d     writes int32_t
 * #8d     writes int64_t
 * i.e.:
 * #1u%lu #2u%lu #4d%lu #8d%lu #llu%hu #d%lu
 *
 * * Attributes:
 *
 * n:  (for network byte order)
 * #ntracetype%ctype
 *            is written in the trace in network byte order.
 *
 * i.e.: #bn4u%lu, #n%lu, #b%u
 *
 * TODO (eventually)
 * Variable length sequence
 * #a #tracetype1 #tracetype2 %array_ptr %elem_size %num_elems
 *            In the trace:
 *            #a specifies that this is a sequence
 *            #tracetype1 is the type of elements in the sequence
 *            #tracetype2 is the type of the element count
 *            GCC input:
 *            array_ptr is a pointer to an array that contains members of size
 *            elem_size.
 *            num_elems is the number of elements in the array.
 * i.e.: #a #lu #lu %p %lu %u
 *
 * Callback
 * #k         callback (taken from the probe data)
 *            The following % arguments are exepected by the callback
 *
 * i.e.: #a #lu #lu #k %p
 *
 * Note: No conversion is done from floats to integers, nor from integers to
 * floats between c types and trace types. float conversion from double to float
 * or from float to double is also not supported.
 *
 * REMOVE
 * %*b     expects sizeof(data), data
 *         where sizeof(data) is 1, 2, 4 or 8
 *
 * Fixed length struct, union or array.
 * FIXME: unable to extract those sizes statically.
 * %*r     expects sizeof(*ptr), ptr
 * %*.*r   expects sizeof(*ptr), __alignof__(*ptr), ptr
 * struct and unions removed.
 * Fixed length array:
 * [%p]#a[len #tracetype]
 * i.e.: [%p]#a[12 #lu]
 *
 * Variable length sequence
 * %*.*:*v expects sizeof(*ptr), __alignof__(*ptr), elem_num, ptr
 *         where elem_num is the number of elements in the sequence
 */
static inline const char *parse_trace_type(const char *fmt,
		char *trace_size, enum ltt_type *trace_type,
		unsigned long *attributes)
{
	int qualifier;		/* 'h', 'l', or 'L' for integer fields */
				/* 'z' support added 23/7/1999 S.H.    */
				/* 'z' changed to 'Z' --davidm 1/25/99 */
				/* 't' added for ptrdiff_t */

	/* parse attributes. */
repeat:
	switch (*fmt) {
	case 'n':
		*attributes |= LTT_ATTRIBUTE_NETWORK_BYTE_ORDER;
		++fmt;
		goto repeat;
	}

	/* get the conversion qualifier */
	qualifier = -1;
	if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L' ||
	    *fmt == 'Z' || *fmt == 'z' || *fmt == 't' ||
	    *fmt == 'S' || *fmt == '1' || *fmt == '2' ||
	    *fmt == '4' || *fmt == 8) {
		qualifier = *fmt;
		++fmt;
		if (qualifier == 'l' && *fmt == 'l') {
			qualifier = 'L';
			++fmt;
		}
	}

	switch (*fmt) {
	case 'c':
		*trace_type = LTT_TYPE_UNSIGNED_INT;
		*trace_size = sizeof(unsigned char);
		goto parse_end;
	case 's':
		*trace_type = LTT_TYPE_STRING;
		goto parse_end;
	case 'p':
		*trace_type = LTT_TYPE_UNSIGNED_INT;
		*trace_size = sizeof(void *);
		goto parse_end;
	case 'd':
	case 'i':
		*trace_type = LTT_TYPE_SIGNED_INT;
		break;
	case 'o':
	case 'u':
	case 'x':
	case 'X':
		*trace_type = LTT_TYPE_UNSIGNED_INT;
		break;
	default:
		if (!*fmt)
			--fmt;
		goto parse_end;
	}
	switch (qualifier) {
	case 'L':
		*trace_size = sizeof(long long);
		break;
	case 'l':
		*trace_size = sizeof(long);
		break;
	case 'Z':
	case 'z':
		*trace_size = sizeof(size_t);
		break;
//ust//	case 't':
//ust//		*trace_size = sizeof(ptrdiff_t);
//ust//		break;
	case 'h':
		*trace_size = sizeof(short);
		break;
	case '1':
		*trace_size = sizeof(uint8_t);
		break;
	case '2':
		*trace_size = sizeof(uint16_t);
		break;
	case '4':
		*trace_size = sizeof(uint32_t);
		break;
	case '8':
		*trace_size = sizeof(uint64_t);
		break;
	default:
		*trace_size = sizeof(int);
	}

parse_end:
	return fmt;
}

/*
 * Restrictions:
 * Field width and precision are *not* supported.
 * %n not supported.
 */
static inline
const char *parse_c_type(const char *fmt, char *c_size, enum ltt_type *c_type,
			 char *outfmt)
{
	int qualifier;		/* 'h', 'l', or 'L' for integer fields */
				/* 'z' support added 23/7/1999 S.H.    */
				/* 'z' changed to 'Z' --davidm 1/25/99 */
				/* 't' added for ptrdiff_t */

	/* process flags : ignore standard print formats for now. */
repeat:
	switch (*fmt) {
	case '-':
	case '+':
	case ' ':
	case '#':
	case '0':
		++fmt;
		goto repeat;
	}

	/* get the conversion qualifier */
	qualifier = -1;
	if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L' ||
	    *fmt == 'Z' || *fmt == 'z' || *fmt == 't' ||
	    *fmt == 'S') {
		qualifier = *fmt;
		++fmt;
		if (qualifier == 'l' && *fmt == 'l') {
			qualifier = 'L';
			++fmt;
		}
	}

	if (outfmt) {
		if (qualifier != -1)
			*outfmt++ = (char)qualifier;
		*outfmt++ = *fmt;
		*outfmt = 0;
	}

	switch (*fmt) {
	case 'c':
		*c_type = LTT_TYPE_UNSIGNED_INT;
		*c_size = sizeof(unsigned char);
		goto parse_end;
	case 's':
		*c_type = LTT_TYPE_STRING;
		goto parse_end;
	case 'p':
		*c_type = LTT_TYPE_UNSIGNED_INT;
		*c_size = sizeof(void *);
		goto parse_end;
	case 'd':
	case 'i':
		*c_type = LTT_TYPE_SIGNED_INT;
		break;
	case 'o':
	case 'u':
	case 'x':
	case 'X':
		*c_type = LTT_TYPE_UNSIGNED_INT;
		break;
	default:
		if (!*fmt)
			--fmt;
		goto parse_end;
	}
	switch (qualifier) {
	case 'L':
		*c_size = sizeof(long long);
		break;
	case 'l':
		*c_size = sizeof(long);
		break;
	case 'Z':
	case 'z':
		*c_size = sizeof(size_t);
		break;
//ust//	case 't':
//ust//		*c_size = sizeof(ptrdiff_t);
//ust//		break;
	case 'h':
		*c_size = sizeof(short);
		break;
	default:
		*c_size = sizeof(int);
	}

parse_end:
	return fmt;
}

static inline size_t serialize_trace_data(struct ust_buffer *buf,
		size_t buf_offset,
		char trace_size, enum ltt_type trace_type,
		char c_size, enum ltt_type c_type,
		int *largest_align, va_list *args)
{
	union {
		unsigned long v_ulong;
		uint64_t v_uint64;
		struct {
			const char *s;
			size_t len;
		} v_string;
	} tmp;

	/*
	 * Be careful about sign extension here.
	 * Sign extension is done with the destination (trace) type.
	 */
	switch (trace_type) {
	case LTT_TYPE_SIGNED_INT:
		switch (c_size) {
		case 1:
			tmp.v_ulong = (long)(int8_t)va_arg(*args, int);
			break;
		case 2:
			tmp.v_ulong = (long)(int16_t)va_arg(*args, int);
			break;
		case 4:
			tmp.v_ulong = (long)(int32_t)va_arg(*args, int);
			break;
		case 8:
			tmp.v_uint64 = va_arg(*args, int64_t);
			break;
		default:
			BUG();
		}
		break;
	case LTT_TYPE_UNSIGNED_INT:
		switch (c_size) {
		case 1:
			tmp.v_ulong = (unsigned long)(uint8_t)va_arg(*args, unsigned int);
			break;
		case 2:
			tmp.v_ulong = (unsigned long)(uint16_t)va_arg(*args, unsigned int);
			break;
		case 4:
			tmp.v_ulong = (unsigned long)(uint32_t)va_arg(*args, unsigned int);
			break;
		case 8:
			tmp.v_uint64 = va_arg(*args, uint64_t);
			break;
		default:
			BUG();
		}
		break;
	case LTT_TYPE_STRING:
		tmp.v_string.s = va_arg(*args, const char *);
		if ((unsigned long)tmp.v_string.s < PAGE_SIZE)
			tmp.v_string.s = "<NULL>";
		tmp.v_string.len = strlen(tmp.v_string.s)+1;
		if (buf)
			ust_buffers_write(buf, buf_offset, tmp.v_string.s,
				tmp.v_string.len);
		buf_offset += tmp.v_string.len;
		goto copydone;
	default:
		BUG();
	}

	/*
	 * If trace_size is lower or equal to 4 bytes, there is no sign
	 * extension to do because we are already encoded in a long. Therefore,
	 * we can combine signed and unsigned ops. 4 bytes float also works
	 * with this, because we do a simple copy of 4 bytes into 4 bytes
	 * without manipulation (and we do not support conversion from integers
	 * to floats).
	 * It is also the case if c_size is 8 bytes, which is the largest
	 * possible integer.
	 */
	if (ltt_get_alignment()) {
		buf_offset += ltt_align(buf_offset, trace_size);
		if (largest_align)
			*largest_align = max_t(int, *largest_align, trace_size);
	}
	if (trace_size <= 4 || c_size == 8) {
		if (buf) {
			switch (trace_size) {
			case 1:
				if (c_size == 8)
					ust_buffers_write(buf, buf_offset,
					(uint8_t[]){ (uint8_t)tmp.v_uint64 },
					sizeof(uint8_t));
				else
					ust_buffers_write(buf, buf_offset,
					(uint8_t[]){ (uint8_t)tmp.v_ulong },
					sizeof(uint8_t));
				break;
			case 2:
				if (c_size == 8)
					ust_buffers_write(buf, buf_offset,
					(uint16_t[]){ (uint16_t)tmp.v_uint64 },
					sizeof(uint16_t));
				else
					ust_buffers_write(buf, buf_offset,
					(uint16_t[]){ (uint16_t)tmp.v_ulong },
					sizeof(uint16_t));
				break;
			case 4:
				if (c_size == 8)
					ust_buffers_write(buf, buf_offset,
					(uint32_t[]){ (uint32_t)tmp.v_uint64 },
					sizeof(uint32_t));
				else
					ust_buffers_write(buf, buf_offset,
					(uint32_t[]){ (uint32_t)tmp.v_ulong },
					sizeof(uint32_t));
				break;
			case 8:
				/*
				 * c_size cannot be other than 8 here because
				 * trace_size > 4.
				 */
				ust_buffers_write(buf, buf_offset,
				(uint64_t[]){ (uint64_t)tmp.v_uint64 },
				sizeof(uint64_t));
				break;
			default:
				BUG();
			}
		}
		buf_offset += trace_size;
		goto copydone;
	} else {
		/*
		 * Perform sign extension.
		 */
		if (buf) {
			switch (trace_type) {
			case LTT_TYPE_SIGNED_INT:
				ust_buffers_write(buf, buf_offset,
					(int64_t[]){ (int64_t)tmp.v_ulong },
					sizeof(int64_t));
				break;
			case LTT_TYPE_UNSIGNED_INT:
				ust_buffers_write(buf, buf_offset,
					(uint64_t[]){ (uint64_t)tmp.v_ulong },
					sizeof(uint64_t));
				break;
			default:
				BUG();
			}
		}
		buf_offset += trace_size;
		goto copydone;
	}

copydone:
	return buf_offset;
}

notrace size_t ltt_serialize_data(struct ust_buffer *buf, size_t buf_offset,
			struct ltt_serialize_closure *closure,
			void *serialize_private, int *largest_align,
			const char *fmt, va_list *args)
{
	char trace_size = 0, c_size = 0;	/*
						 * 0 (unset), 1, 2, 4, 8 bytes.
						 */
	enum ltt_type trace_type = LTT_TYPE_NONE, c_type = LTT_TYPE_NONE;
	unsigned long attributes = 0;

	for (; *fmt ; ++fmt) {
		switch (*fmt) {
		case '#':
			/* tracetypes (#) */
			++fmt;			/* skip first '#' */
			if (*fmt == '#')	/* Escaped ## */
				break;
			attributes = 0;
			fmt = parse_trace_type(fmt, &trace_size, &trace_type,
				&attributes);
			break;
		case '%':
			/* c types (%) */
			++fmt;			/* skip first '%' */
			if (*fmt == '%')	/* Escaped %% */
				break;
			fmt = parse_c_type(fmt, &c_size, &c_type, NULL);
			/*
			 * Output c types if no trace types has been
			 * specified.
			 */
			if (!trace_size)
				trace_size = c_size;
			if (trace_type == LTT_TYPE_NONE)
				trace_type = c_type;
			if (c_type == LTT_TYPE_STRING)
				trace_type = LTT_TYPE_STRING;
			/* perform trace write */
			buf_offset = serialize_trace_data(buf,
						buf_offset, trace_size,
						trace_type, c_size, c_type,
						largest_align, args);
			trace_size = 0;
			c_size = 0;
			trace_type = LTT_TYPE_NONE;
			c_size = LTT_TYPE_NONE;
			attributes = 0;
			break;
			/* default is to skip the text, doing nothing */
		}
	}
	return buf_offset;
}

/*
 * Calculate data size
 * Assume that the padding for alignment starts at a sizeof(void *) address.
 */
static notrace size_t ltt_get_data_size(struct ltt_serialize_closure *closure,
				void *serialize_private, int *largest_align,
				const char *fmt, va_list *args)
{
	ltt_serialize_cb cb = closure->callbacks[0];
	closure->cb_idx = 0;
	return (size_t)cb(NULL, 0, closure, serialize_private,
				largest_align, fmt, args);
}

static notrace
void ltt_write_event_data(struct ust_buffer *buf, size_t buf_offset,
				struct ltt_serialize_closure *closure,
				void *serialize_private, int largest_align,
				const char *fmt, va_list *args)
{
	ltt_serialize_cb cb = closure->callbacks[0];
	closure->cb_idx = 0;
	buf_offset += ltt_align(buf_offset, largest_align);
	cb(buf, buf_offset, closure, serialize_private, NULL, fmt, args);
}


notrace void ltt_vtrace(const struct marker *mdata, void *probe_data,
			struct registers *regs, void *call_data,
			const char *fmt, va_list *args)
{
	int largest_align, ret;
	struct ltt_active_marker *pdata;
	uint16_t eID;
	size_t data_size, slot_size;
	unsigned int chan_index;
	struct ust_channel *channel;
	struct ust_trace *trace, *dest_trace = NULL;
	struct ust_buffer *buf;
	void *transport_data;
	u64 tsc;
	long buf_offset;
	va_list args_copy;
	struct ltt_serialize_closure closure;
	struct ltt_probe_private_data *private_data = call_data;
	void *serialize_private = NULL;
	int cpu;
	unsigned int rflags;

	/*
	 * This test is useful for quickly exiting static tracing when no trace
	 * is active. We expect to have an active trace when we get here.
	 */
	if (unlikely(ltt_traces.num_active_traces == 0))
		return;

	rcu_read_lock(); //ust// rcu_read_lock_sched_notrace();
	cpu = ust_get_cpu();

	/* Force volatile access. */
	STORE_SHARED(ltt_nesting, LOAD_SHARED(ltt_nesting) + 1);
	barrier();

	pdata = (struct ltt_active_marker *)probe_data;
	eID = mdata->event_id;
	chan_index = mdata->channel_id;
	closure.callbacks = pdata->probe->callbacks;

	if (unlikely(private_data)) {
		dest_trace = private_data->trace;
		if (private_data->serializer)
			closure.callbacks = &private_data->serializer;
		serialize_private = private_data->serialize_private;
	}

	va_copy(args_copy, *args);
	/*
	 * Assumes event payload to start on largest_align alignment.
	 */
	largest_align = 1;	/* must be non-zero for ltt_align */
	data_size = ltt_get_data_size(&closure, serialize_private,
					&largest_align, fmt, &args_copy);
	largest_align = min_t(int, largest_align, sizeof(void *));
	va_end(args_copy);

	/* Iterate on each trace */
	list_for_each_entry_rcu(trace, &ltt_traces.head, list) {
		/*
		 * Expect the filter to filter out events. If we get here,
		 * we went through tracepoint activation as a first step.
		 */
		if (unlikely(dest_trace && trace != dest_trace))
			continue;
		if (unlikely(!trace->active))
			continue;
		if (unlikely(!ltt_run_filter(trace, eID)))
			continue;
#ifdef CONFIG_LTT_DEBUG_EVENT_SIZE
		rflags = LTT_RFLAG_ID_SIZE;
#else
		if (unlikely(eID >= LTT_FREE_EVENTS))
			rflags = LTT_RFLAG_ID;
		else
			rflags = 0;
#endif
		/*
		 * Skip channels added after trace creation.
		 */
		if (unlikely(chan_index >= trace->nr_channels))
			continue;
		channel = &trace->channels[chan_index];
		if (!channel->active)
			continue;

		/* If a new cpu was plugged since the trace was started, we did
		 * not add it to the trace, and therefore we write the event to
		 * cpu 0.
		 */
		if(cpu >= channel->n_cpus) {
			cpu = 0;
		}

		/* reserve space : header and data */
		ret = ltt_reserve_slot(channel, trace, data_size, largest_align,
					cpu, &buf, &slot_size, &buf_offset,
					&tsc, &rflags);
		if (unlikely(ret < 0))
			continue; /* buffer full */

		va_copy(args_copy, *args);
		/* FIXME : could probably encapsulate transport better. */
//ust//		buf = ((struct rchan *)channel->trans_channel_data)->buf[cpu];
		buf = channel->buf[cpu];
		/* Out-of-order write : header and data */
		buf_offset = ltt_write_event_header(channel, buf, buf_offset,
					eID, data_size, tsc, rflags);
		ltt_write_event_data(buf, buf_offset, &closure,
					serialize_private,
					largest_align, fmt, &args_copy);
		va_end(args_copy);
		/* Out-of-order commit */
		ltt_commit_slot(channel, buf, buf_offset, data_size, slot_size);
		DBG("just commited event (%s/%s) at offset %ld and size %zd", mdata->channel, mdata->name, buf_offset, slot_size);
	}

	barrier();
	STORE_SHARED(ltt_nesting, LOAD_SHARED(ltt_nesting) - 1);

	rcu_read_unlock(); //ust// rcu_read_unlock_sched_notrace();
}

notrace void ltt_trace(const struct marker *mdata, void *probe_data,
		       struct registers *regs, void *call_data,
		       const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ltt_vtrace(mdata, probe_data, regs, call_data, fmt, &args);
	va_end(args);
}

static notrace void skip_space(const char **ps)
{
	while(**ps == ' ')
		(*ps)++;
}

static notrace void copy_token(char **out, const char **in)
{
	while(**in != ' ' && **in != '\0') {
		**out = **in;
		(*out)++;
		(*in)++;
	}
}

/* serialize_to_text
 *
 * Given a format string and a va_list of arguments, convert them to a
 * human-readable string.
 *
 * @outbuf: the buffer to output the string to
 * @bufsize: the max size that can be used in outbuf
 * @fmt: the marker format string
 * @ap: a va_list that contains the arguments corresponding to fmt
 *
 * Return value: the number of chars that have been put in outbuf, excluding
 * the final \0, or, if the buffer was too small, the number of chars that
 * would have been written in outbuf if it had been large enough.
 *
 * outbuf may be NULL. The return value may then be used be allocate an
 * appropriate outbuf.
 *
 */

notrace
int serialize_to_text(char *outbuf, int bufsize, const char *fmt, va_list ap)
{
	int fmt_len = strlen(fmt);
	char *new_fmt = alloca(fmt_len + 1);
	const char *orig_fmt_p = fmt;
	char *new_fmt_p = new_fmt;
	char false_buf;
	int result;
	enum { none, cfmt, tracefmt, argname } prev_token = none;

	while(*orig_fmt_p != '\0') {
		if(*orig_fmt_p == '%') {
			prev_token = cfmt;
			copy_token(&new_fmt_p, &orig_fmt_p);
		}
		else if(*orig_fmt_p == '#') {
			prev_token = tracefmt;
			do {
				orig_fmt_p++;
			} while(*orig_fmt_p != ' ' && *orig_fmt_p != '\0');
		}
		else if(*orig_fmt_p == ' ') {
			if(prev_token == argname) {
				*new_fmt_p = '=';
				new_fmt_p++;
			}
			else if(prev_token == cfmt) {
				*new_fmt_p = ' ';
				new_fmt_p++;
			}

			skip_space(&orig_fmt_p);
		}
		else {
			prev_token = argname;
			copy_token(&new_fmt_p, &orig_fmt_p);
		}
	}

	*new_fmt_p = '\0';

	if(outbuf == NULL) {
		/* use this false_buffer for compatibility with pre-C99 */
		outbuf = &false_buf;
		bufsize = 1;
	}
	result = ust_safe_vsnprintf(outbuf, bufsize, new_fmt, ap);

	return result;
}
