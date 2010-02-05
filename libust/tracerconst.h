#ifndef TRACERCONST_H
#define TRACERCONST_H

/* Hardcoded event headers
 *
 * event header for a trace with active heartbeat : 27 bits timestamps
 *
 * headers are 32-bits aligned. In order to insure such alignment, a dynamic per
 * trace alignment value must be done.
 *
 * Remember that the C compiler does align each member on the boundary
 * equivalent to their own size.
 *
 * As relay subbuffers are aligned on pages, we are sure that they are 4 and 8
 * bytes aligned, so the buffer header and trace header are aligned.
 *
 * Event headers are aligned depending on the trace alignment option.
 *
 * Note using C structure bitfields for cross-endianness and portability
 * concerns.
 */

#define LTT_RESERVED_EVENTS	3
#define LTT_EVENT_BITS		5
#define LTT_FREE_EVENTS		((1 << LTT_EVENT_BITS) - LTT_RESERVED_EVENTS)
#define LTT_TSC_BITS		27
#define LTT_TSC_MASK		((1 << LTT_TSC_BITS) - 1)

struct ltt_event_header {
	u32 id_time;		/* 5 bits event id (MSB); 27 bits time (LSB) */
};

/* Reservation flags */
#define	LTT_RFLAG_ID			(1 << 0)
#define	LTT_RFLAG_ID_SIZE		(1 << 1)
#define	LTT_RFLAG_ID_SIZE_TSC		(1 << 2)

#define LTT_MAX_SMALL_SIZE              0xFFFFU

#endif /* TRACERCONST_H */
