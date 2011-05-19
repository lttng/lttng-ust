#ifndef _LTT_TYPE_SERIALIZER_H
#define _LTT_TYPE_SERIALIZER_H

#include <ust/marker.h>
#include <ust/marker-internal.h>
#include <ust/core.h>

/*
 * largest_align must be non-zero, equal to the minimum between the largest type
 * and sizeof(void *).
 */
extern void _ltt_specialized_trace(const struct ust_marker *mdata, void *probe_data,
		void *serialize_private, unsigned int data_size,
		unsigned int largest_align);

/*
 * Statically check that 0 < largest_align < sizeof(void *) to make sure it is
 * dumb-proof. It will make sure 0 is changed into 1 and unsigned long long is
 * changed into sizeof(void *) on 32-bit architectures.
 */
static inline void ltt_specialized_trace(const struct ust_marker *mdata,
		void *probe_data,
		void *serialize_private, unsigned int data_size,
		unsigned int largest_align)
{
	largest_align = min_t(unsigned int, largest_align, sizeof(void *));
	largest_align = max_t(unsigned int, largest_align, 1);
	_ltt_specialized_trace(mdata, probe_data, serialize_private, data_size,
		largest_align);
}

/*
 * Type serializer definitions.
 */

/*
 * Return size of structure without end-of-structure padding.
 */
#define serialize_sizeof(type)	offsetof(typeof(type), end_field)

struct serialize_long_int {
	unsigned long f1;
	unsigned int f2;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_int_int_long {
	unsigned int f1;
	unsigned int f2;
	unsigned long f3;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_int_int_short {
	unsigned int f1;
	unsigned int f2;
	unsigned short f3;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_long_long {
	unsigned long f1;
	unsigned long f2;
	unsigned long f3;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_long_int {
	unsigned long f1;
	unsigned long f2;
	unsigned int f3;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_long_short_char {
	unsigned long f1;
	unsigned long f2;
	unsigned short f3;
	unsigned char f4;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_long_short {
	unsigned long f1;
	unsigned long f2;
	unsigned short f3;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_short_char {
	unsigned long f1;
	unsigned short f2;
	unsigned char f3;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_short {
	unsigned long f1;
	unsigned short f2;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_char {
	unsigned long f1;
	unsigned char f2;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_sizet_int {
	size_t f1;
	unsigned int f2;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_long_sizet_int {
	unsigned long f1;
	unsigned long f2;
	size_t f3;
	unsigned int f4;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_long_long_sizet_int_int {
	unsigned long f1;
	unsigned long f2;
	size_t f3;
	unsigned int f4;
	unsigned int f5;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_l4421224411111 {
	unsigned long f1;
	uint32_t f2;
	uint32_t f3;
	uint16_t f4;
	uint8_t f5;
	uint16_t f6;
	uint16_t f7;
	uint32_t f8;
	uint32_t f9;
	uint8_t f10;
	uint8_t f11;
	uint8_t f12;
	uint8_t f13;
	uint8_t f14;
	unsigned char end_field[0];
} LTT_ALIGN;

struct serialize_l214421224411111 {
	unsigned long f1;
	uint16_t f2;
	uint8_t f3;
	uint32_t f4;
	uint32_t f5;
	uint16_t f6;
	uint8_t f7;
	uint16_t f8;
	uint16_t f9;
	uint32_t f10;
	uint32_t f11;
	uint8_t f12;
	uint8_t f13;
	uint8_t f14;
	uint8_t f15;
	uint8_t f16;
	uint8_t end_field[0];
} LTT_ALIGN;

struct serialize_l4412228 {
	unsigned long f1;
	uint32_t f2;
	uint32_t f3;
	uint8_t f4;
	uint16_t f5;
	uint16_t f6;
	uint16_t f7;
	uint64_t f8;
	unsigned char end_field[0];
} LTT_ALIGN;

#endif /* _LTT_TYPE_SERIALIZER_H */
