/*
 * Copyright (C) 2008 - Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
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

#ifndef UST_HEADER_INLINE_H
#define UST_HEADER_INLINE_H

#include "tracercore.h"

/*
 * ust_get_header_size
 *
 * Calculate alignment offset to 32-bits. This is the alignment offset of the
 * event header.
 *
 * Important note :
 * The event header must be 32-bits. The total offset calculated here :
 *
 * Alignment of header struct on 32 bits (min arch size, header size)
 * + sizeof(header struct)  (32-bits)
 * + (opt) u16 (ext. event id)
 * + (opt) u16 (event_size) (if event_size == 0xFFFFUL, has ext. event size)
 * + (opt) u32 (ext. event size)
 * + (opt) u64 full TSC (aligned on min(64-bits, arch size))
 *
 * The payload must itself determine its own alignment from the biggest type it
 * contains.
 * */
static __inline__ unsigned char ust_get_header_size(
		struct ust_channel *channel,
		size_t offset,
		size_t data_size,
		size_t *before_hdr_pad,
		unsigned int rflags)
{
	size_t orig_offset = offset;
	size_t padding;

	padding = ltt_align(offset, sizeof(struct ltt_event_header));
	offset += padding;
	offset += sizeof(struct ltt_event_header);

	if(unlikely(rflags)) {
		switch (rflags) {
		case LTT_RFLAG_ID_SIZE_TSC:
			offset += sizeof(u16) + sizeof(u16);
			if (data_size >= 0xFFFFU)
				offset += sizeof(u32);
			offset += ltt_align(offset, sizeof(u64));
			offset += sizeof(u64);
			break;
		case LTT_RFLAG_ID_SIZE:
			offset += sizeof(u16) + sizeof(u16);
			if (data_size >= 0xFFFFU)
				offset += sizeof(u32);
			break;
		case LTT_RFLAG_ID:
			offset += sizeof(u16);
			break;
		}
	}

	*before_hdr_pad = padding;
	return offset - orig_offset;
}

#endif /* UST_HEADER_INLINE_H */
