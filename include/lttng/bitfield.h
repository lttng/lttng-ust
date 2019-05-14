#ifndef _BABELTRACE_BITFIELD_H
#define _BABELTRACE_BITFIELD_H

/*
 * Copyright 2010-2019 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdint.h>	/* C99 5.2.4.2 Numerical limits */
#include <limits.h>	/* C99 5.2.4.2 Numerical limits */
#include <stdbool.h>	/* C99 7.16 bool type */
#include <lttng/ust-endian.h>	/* Non-standard BIG_ENDIAN, LITTLE_ENDIAN, BYTE_ORDER */

/*
 * This header strictly follows the C99 standard, except for use of the
 * compiler-specific __typeof__.
 */

/*
 * This bitfield header requires the compiler representation of signed
 * integers to be two's complement.
 */
#if (-1 != ~0)
#error "bitfield.h requires the compiler representation of signed integers to be two's complement."
#endif

/*
 * _bt_is_signed_type() willingly generates comparison of unsigned
 * expression < 0, which is always false. Silence compiler warnings.
 */
#ifdef __GNUC__
# define _BT_DIAG_PUSH			_Pragma("GCC diagnostic push")
# define _BT_DIAG_POP			_Pragma("GCC diagnostic pop")

# define _BT_DIAG_STRINGIFY_1(x)	#x
# define _BT_DIAG_STRINGIFY(x)		_BT_DIAG_STRINGIFY_1(x)

# define _BT_DIAG_IGNORE(option)	\
	_Pragma(_BT_DIAG_STRINGIFY(GCC diagnostic ignored option))
# define _BT_DIAG_IGNORE_TYPE_LIMITS	_BT_DIAG_IGNORE("-Wtype-limits")
#else
# define _BT_DIAG_PUSH
# define _BT_DIAG_POP
# define _BT_DIAG_IGNORE
#endif

#define _bt_is_signed_type(type)	((type) -1 < (type) 0)

/*
 * Produce a build-time error if the condition `cond` is non-zero.
 * Evaluates as a size_t expression.
 */
#define _BT_BUILD_ASSERT(cond)					\
	sizeof(struct { int f:(2 * !!(cond) - 1); })

/*
 * Cast value `v` to an unsigned integer of the same size as `v`.
 */
#define _bt_cast_value_to_unsigned(v)					\
	(sizeof(v) == sizeof(uint8_t) ? (uint8_t) (v) :			\
	sizeof(v) == sizeof(uint16_t) ? (uint16_t) (v) :		\
	sizeof(v) == sizeof(uint32_t) ? (uint32_t) (v) :		\
	sizeof(v) == sizeof(uint64_t) ? (uint64_t) (v) :		\
	_BT_BUILD_ASSERT(sizeof(v) <= sizeof(uint64_t)))

/*
 * Cast value `v` to an unsigned integer type of the size of type `type`
 * *without* sign-extension.
 *
 * The unsigned cast ensures that we're not shifting a negative value,
 * which is undefined in C. However, this limits the maximum type size
 * of `type` to 64-bit. Generate a compile-time error if the size of
 * `type` is larger than 64-bit.
 */
#define _bt_cast_value_to_unsigned_type(type, v)			\
	(sizeof(type) == sizeof(uint8_t) ?				\
		(uint8_t) _bt_cast_value_to_unsigned(v) :		\
	sizeof(type) == sizeof(uint16_t) ?				\
		(uint16_t) _bt_cast_value_to_unsigned(v) :		\
	sizeof(type) == sizeof(uint32_t) ?				\
		(uint32_t) _bt_cast_value_to_unsigned(v) :		\
	sizeof(type) == sizeof(uint64_t) ?				\
		(uint64_t) _bt_cast_value_to_unsigned(v) :		\
	_BT_BUILD_ASSERT(sizeof(v) <= sizeof(uint64_t)))

/*
 * _bt_fill_mask evaluates to a "type" integer with all bits set.
 */
#define _bt_fill_mask(type)	((type) ~(type) 0)

/*
 * Left shift a value `v` of `shift` bits.
 *
 * The type of `v` can be signed or unsigned integer.
 * The value of `shift` must be less than the size of `v` (in bits),
 * otherwise the behavior is undefined.
 * Evaluates to the result of the shift operation.
 *
 * According to the C99 standard, left shift of a left hand-side signed
 * type is undefined if it has a negative value or if the result cannot
 * be represented in the result type. This bitfield header discards the
 * bits that are left-shifted beyond the result type representation,
 * which is the behavior of an unsigned type left shift operation.
 * Therefore, always perform left shift on an unsigned type.
 *
 * This macro should not be used if `shift` can be greater or equal than
 * the bitwidth of `v`. See `_bt_safe_lshift`.
 */
#define _bt_lshift(v, shift)						\
	((__typeof__(v)) (_bt_cast_value_to_unsigned(v) << (shift)))

/*
 * Generate a mask of type `type` with the `length` least significant bits
 * cleared, and the most significant bits set.
 */
#define _bt_make_mask_complement(type, length)				\
	_bt_lshift(_bt_fill_mask(type), length)

/*
 * Generate a mask of type `type` with the `length` least significant bits
 * set, and the most significant bits cleared.
 */
#define _bt_make_mask(type, length)					\
	((type) ~_bt_make_mask_complement(type, length))

/*
 * Right shift a value `v` of `shift` bits.
 *
 * The type of `v` can be signed or unsigned integer.
 * The value of `shift` must be less than the size of `v` (in bits),
 * otherwise the behavior is undefined.
 * Evaluates to the result of the shift operation.
 *
 * According to the C99 standard, right shift of a left hand-side signed
 * type which has a negative value is implementation defined. This
 * bitfield header relies on the right shift implementation carrying the
 * sign bit. If the compiler implementation has a different behavior,
 * emulate carrying the sign bit.
 *
 * This macro should not be used if `shift` can be greater or equal than
 * the bitwidth of `v`. See `_bt_safe_rshift`.
 */
#if ((-1 >> 1) == -1)
#define _bt_rshift(v, shift)	((v) >> (shift))
#else
#define _bt_rshift(v, shift)						\
	((__typeof__(v)) ((_bt_cast_value_to_unsigned(v) >> (shift)) |	\
		((v) < 0 ? _bt_make_mask_complement(__typeof__(v),	\
			sizeof(v) * CHAR_BIT - (shift)) : 0)))
#endif

/*
 * Right shift a signed or unsigned integer with `shift` value being an
 * arbitrary number of bits. `v` is modified by this macro. The shift
 * is transformed into a sequence of `_nr_partial_shifts` consecutive
 * shift operations, each of a number of bits smaller than the bitwidth
 * of `v`, ending with a shift of the number of left over bits.
 */
#define _bt_safe_rshift(v, shift)					\
do {									\
	unsigned long _nr_partial_shifts = (shift) / (sizeof(v) * CHAR_BIT - 1); \
	unsigned long _leftover_bits = (shift) % (sizeof(v) * CHAR_BIT - 1); \
									\
	for (; _nr_partial_shifts; _nr_partial_shifts--)		\
		(v) = _bt_rshift(v, sizeof(v) * CHAR_BIT - 1);		\
	(v) = _bt_rshift(v, _leftover_bits);				\
} while (0)

/*
 * Left shift a signed or unsigned integer with `shift` value being an
 * arbitrary number of bits. `v` is modified by this macro. The shift
 * is transformed into a sequence of `_nr_partial_shifts` consecutive
 * shift operations, each of a number of bits smaller than the bitwidth
 * of `v`, ending with a shift of the number of left over bits.
 */
#define _bt_safe_lshift(v, shift)					\
do {									\
	unsigned long _nr_partial_shifts = (shift) / (sizeof(v) * CHAR_BIT - 1); \
	unsigned long _leftover_bits = (shift) % (sizeof(v) * CHAR_BIT - 1); \
									\
	for (; _nr_partial_shifts; _nr_partial_shifts--)		\
		(v) = _bt_lshift(v, sizeof(v) * CHAR_BIT - 1);		\
	(v) = _bt_lshift(v, _leftover_bits);				\
} while (0)

/*
 * bt_bitfield_write - write integer to a bitfield in native endianness
 *
 * Save integer to the bitfield, which starts at the "start" bit, has "len"
 * bits.
 * The inside of a bitfield is from high bits to low bits.
 * Uses native endianness.
 * For unsigned "v", pad MSB with 0 if bitfield is larger than v.
 * For signed "v", sign-extend v if bitfield is larger than v.
 *
 * On little endian, bytes are placed from the less significant to the most
 * significant. Also, consecutive bitfields are placed from lower bits to higher
 * bits.
 *
 * On big endian, bytes are places from most significant to less significant.
 * Also, consecutive bitfields are placed from higher to lower bits.
 */

#define _bt_bitfield_write_le(_ptr, type, _start, _length, _v)		\
do {									\
	__typeof__(_v) __v = (_v);					\
	type *__ptr = (void *) (_ptr);					\
	unsigned long __start = (_start), __length = (_length);		\
	type mask, cmask;						\
	unsigned long ts = sizeof(type) * CHAR_BIT; /* type size */	\
	unsigned long start_unit, end_unit, this_unit;			\
	unsigned long end, cshift; /* cshift is "complement shift" */	\
									\
	if (!__length)							\
		break;							\
									\
	end = __start + __length;					\
	start_unit = __start / ts;					\
	end_unit = (end + (ts - 1)) / ts;				\
									\
	/* Trim v high bits */						\
	if (__length < sizeof(__v) * CHAR_BIT)				\
		__v &= _bt_make_mask(__typeof__(__v), __length);	\
									\
	/* We can now append v with a simple "or", shift it piece-wise */ \
	this_unit = start_unit;						\
	if (start_unit == end_unit - 1) {				\
		mask = _bt_make_mask(type, __start % ts);		\
		if (end % ts)						\
			mask |= _bt_make_mask_complement(type, end % ts); \
		cmask = _bt_lshift((type) (__v), __start % ts);		\
		cmask &= ~mask;						\
		__ptr[this_unit] &= mask;				\
		__ptr[this_unit] |= cmask;				\
		break;							\
	}								\
	if (__start % ts) {						\
		cshift = __start % ts;					\
		mask = _bt_make_mask(type, cshift);			\
		cmask = _bt_lshift((type) (__v), cshift);		\
		cmask &= ~mask;						\
		__ptr[this_unit] &= mask;				\
		__ptr[this_unit] |= cmask;				\
		_bt_safe_rshift(__v, ts - cshift);			\
		__start += ts - cshift;					\
		this_unit++;						\
	}								\
	for (; this_unit < end_unit - 1; this_unit++) {			\
		__ptr[this_unit] = (type) __v;				\
		_bt_safe_rshift(__v, ts);				\
		__start += ts;						\
	}								\
	if (end % ts) {							\
		mask = _bt_make_mask_complement(type, end % ts);	\
		cmask = (type) __v;					\
		cmask &= ~mask;						\
		__ptr[this_unit] &= mask;				\
		__ptr[this_unit] |= cmask;				\
	} else								\
		__ptr[this_unit] = (type) __v;				\
} while (0)

#define _bt_bitfield_write_be(_ptr, type, _start, _length, _v)		\
do {									\
	__typeof__(_v) __v = (_v);					\
	type *__ptr = (void *) (_ptr);					\
	unsigned long __start = (_start), __length = (_length);		\
	type mask, cmask;						\
	unsigned long ts = sizeof(type) * CHAR_BIT; /* type size */	\
	unsigned long start_unit, end_unit, this_unit;			\
	unsigned long end, cshift; /* cshift is "complement shift" */	\
									\
	if (!__length)							\
		break;							\
									\
	end = __start + __length;					\
	start_unit = __start / ts;					\
	end_unit = (end + (ts - 1)) / ts;				\
									\
	/* Trim v high bits */						\
	if (__length < sizeof(__v) * CHAR_BIT)				\
		__v &= _bt_make_mask(__typeof__(__v), __length);	\
									\
	/* We can now append v with a simple "or", shift it piece-wise */ \
	this_unit = end_unit - 1;					\
	if (start_unit == end_unit - 1) {				\
		mask = _bt_make_mask(type, (ts - (end % ts)) % ts);	\
		if (__start % ts)					\
			mask |= _bt_make_mask_complement(type, ts - (__start % ts)); \
		cmask = _bt_lshift((type) (__v), (ts - (end % ts)) % ts); \
		cmask &= ~mask;						\
		__ptr[this_unit] &= mask;				\
		__ptr[this_unit] |= cmask;				\
		break;							\
	}								\
	if (end % ts) {							\
		cshift = end % ts;					\
		mask = _bt_make_mask(type, ts - cshift);		\
		cmask = _bt_lshift((type) (__v), ts - cshift);		\
		cmask &= ~mask;						\
		__ptr[this_unit] &= mask;				\
		__ptr[this_unit] |= cmask;				\
		_bt_safe_rshift(__v, cshift);				\
		end -= cshift;						\
		this_unit--;						\
	}								\
	for (; (long) this_unit >= (long) start_unit + 1; this_unit--) { \
		__ptr[this_unit] = (type) __v;				\
		_bt_safe_rshift(__v, ts);				\
		end -= ts;						\
	}								\
	if (__start % ts) {						\
		mask = _bt_make_mask_complement(type, ts - (__start % ts)); \
		cmask = (type) __v;					\
		cmask &= ~mask;						\
		__ptr[this_unit] &= mask;				\
		__ptr[this_unit] |= cmask;				\
	} else								\
		__ptr[this_unit] = (type) __v;				\
} while (0)

/*
 * bt_bitfield_write - write integer to a bitfield in native endianness
 * bt_bitfield_write_le - write integer to a bitfield in little endian
 * bt_bitfield_write_be - write integer to a bitfield in big endian
 */

#if (BYTE_ORDER == LITTLE_ENDIAN)

#define bt_bitfield_write(ptr, type, _start, _length, _v)		\
	_bt_bitfield_write_le(ptr, type, _start, _length, _v)

#define bt_bitfield_write_le(ptr, type, _start, _length, _v)		\
	_bt_bitfield_write_le(ptr, type, _start, _length, _v)

#define bt_bitfield_write_be(ptr, type, _start, _length, _v)		\
	_bt_bitfield_write_be(ptr, unsigned char, _start, _length, _v)

#elif (BYTE_ORDER == BIG_ENDIAN)

#define bt_bitfield_write(ptr, type, _start, _length, _v)		\
	_bt_bitfield_write_be(ptr, type, _start, _length, _v)

#define bt_bitfield_write_le(ptr, type, _start, _length, _v)		\
	_bt_bitfield_write_le(ptr, unsigned char, _start, _length, _v)

#define bt_bitfield_write_be(ptr, type, _start, _length, _v)		\
	_bt_bitfield_write_be(ptr, type, _start, _length, _v)

#else /* (BYTE_ORDER == PDP_ENDIAN) */

#error "Byte order not supported"

#endif

#define _bt_bitfield_read_le(_ptr, type, _start, _length, _vptr)	\
do {									\
	__typeof__(*(_vptr)) *__vptr = (_vptr);				\
	__typeof__(*__vptr) __v;					\
	type *__ptr = (void *) (_ptr);					\
	unsigned long __start = (_start), __length = (_length);		\
	type mask, cmask;						\
	unsigned long ts = sizeof(type) * CHAR_BIT; /* type size */	\
	unsigned long start_unit, end_unit, this_unit;			\
	unsigned long end, cshift; /* cshift is "complement shift" */	\
	bool is_signed_type;						\
									\
	if (!__length) {						\
		*__vptr = 0;						\
		break;							\
	}								\
									\
	end = __start + __length;					\
	start_unit = __start / ts;					\
	end_unit = (end + (ts - 1)) / ts;				\
									\
	this_unit = end_unit - 1;					\
	_BT_DIAG_PUSH							\
	_BT_DIAG_IGNORE_TYPE_LIMITS					\
	is_signed_type = _bt_is_signed_type(__typeof__(__v));		\
	_BT_DIAG_POP							\
	if (is_signed_type						\
	    && (__ptr[this_unit] & _bt_lshift((type) 1, (end % ts ? end % ts : ts) - 1))) \
		__v = ~(__typeof__(__v)) 0;				\
	else								\
		__v = 0;						\
	if (start_unit == end_unit - 1) {				\
		cmask = __ptr[this_unit];				\
		cmask = _bt_rshift(cmask, __start % ts);		\
		if ((end - __start) % ts) {				\
			mask = _bt_make_mask(type, end - __start);	\
			cmask &= mask;					\
		}							\
		_bt_safe_lshift(__v, end - __start);			\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), cmask); \
		*__vptr = __v;						\
		break;							\
	}								\
	if (end % ts) {							\
		cshift = end % ts;					\
		mask = _bt_make_mask(type, cshift);			\
		cmask = __ptr[this_unit];				\
		cmask &= mask;						\
		_bt_safe_lshift(__v, cshift);				\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), cmask); \
		end -= cshift;						\
		this_unit--;						\
	}								\
	for (; (long) this_unit >= (long) start_unit + 1; this_unit--) { \
		_bt_safe_lshift(__v, ts);				\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), __ptr[this_unit]); \
		end -= ts;						\
	}								\
	if (__start % ts) {						\
		mask = _bt_make_mask(type, ts - (__start % ts));	\
		cmask = __ptr[this_unit];				\
		cmask = _bt_rshift(cmask, __start % ts);		\
		cmask &= mask;						\
		_bt_safe_lshift(__v, ts - (__start % ts));		\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), cmask); \
	} else {							\
		_bt_safe_lshift(__v, ts);				\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), __ptr[this_unit]); \
	}								\
	*__vptr = __v;							\
} while (0)

#define _bt_bitfield_read_be(_ptr, type, _start, _length, _vptr)	\
do {									\
	__typeof__(*(_vptr)) *__vptr = (_vptr);				\
	__typeof__(*__vptr) __v;					\
	type *__ptr = (void *) (_ptr);					\
	unsigned long __start = (_start), __length = (_length);		\
	type mask, cmask;						\
	unsigned long ts = sizeof(type) * CHAR_BIT; /* type size */	\
	unsigned long start_unit, end_unit, this_unit;			\
	unsigned long end, cshift; /* cshift is "complement shift" */	\
	bool is_signed_type;						\
									\
	if (!__length) {						\
		*__vptr = 0;						\
		break;							\
	}								\
									\
	end = __start + __length;					\
	start_unit = __start / ts;					\
	end_unit = (end + (ts - 1)) / ts;				\
									\
	this_unit = start_unit;						\
	_BT_DIAG_PUSH							\
	_BT_DIAG_IGNORE_TYPE_LIMITS					\
	is_signed_type = _bt_is_signed_type(__typeof__(__v));		\
	_BT_DIAG_POP							\
	if (is_signed_type						\
	    && (__ptr[this_unit] & _bt_lshift((type) 1, ts - (__start % ts) - 1))) \
		__v = ~(__typeof__(__v)) 0;				\
	else								\
		__v = 0;						\
	if (start_unit == end_unit - 1) {				\
		cmask = __ptr[this_unit];				\
		cmask = _bt_rshift(cmask, (ts - (end % ts)) % ts);	\
		if ((end - __start) % ts) {				\
			mask = _bt_make_mask(type, end - __start);	\
			cmask &= mask;					\
		}							\
		_bt_safe_lshift(__v, end - __start);		\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), cmask); \
		*__vptr = __v;						\
		break;							\
	}								\
	if (__start % ts) {						\
		cshift = __start % ts;					\
		mask = _bt_make_mask(type, ts - cshift);		\
		cmask = __ptr[this_unit];				\
		cmask &= mask;						\
		_bt_safe_lshift(__v, ts - cshift);			\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), cmask); \
		__start += ts - cshift;					\
		this_unit++;						\
	}								\
	for (; this_unit < end_unit - 1; this_unit++) {			\
		_bt_safe_lshift(__v, ts);				\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), __ptr[this_unit]); \
		__start += ts;						\
	}								\
	if (end % ts) {							\
		mask = _bt_make_mask(type, end % ts);			\
		cmask = __ptr[this_unit];				\
		cmask = _bt_rshift(cmask, ts - (end % ts));		\
		cmask &= mask;						\
		_bt_safe_lshift(__v, end % ts);				\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), cmask); \
	} else {							\
		_bt_safe_lshift(__v, ts);				\
		__v |= _bt_cast_value_to_unsigned_type(__typeof__(__v), __ptr[this_unit]); \
	}								\
	*__vptr = __v;							\
} while (0)

/*
 * bt_bitfield_read - read integer from a bitfield in native endianness
 * bt_bitfield_read_le - read integer from a bitfield in little endian
 * bt_bitfield_read_be - read integer from a bitfield in big endian
 */

#if (BYTE_ORDER == LITTLE_ENDIAN)

#define bt_bitfield_read(_ptr, type, _start, _length, _vptr)		\
	_bt_bitfield_read_le(_ptr, type, _start, _length, _vptr)

#define bt_bitfield_read_le(_ptr, type, _start, _length, _vptr)		\
	_bt_bitfield_read_le(_ptr, type, _start, _length, _vptr)

#define bt_bitfield_read_be(_ptr, type, _start, _length, _vptr)		\
	_bt_bitfield_read_be(_ptr, unsigned char, _start, _length, _vptr)

#elif (BYTE_ORDER == BIG_ENDIAN)

#define bt_bitfield_read(_ptr, type, _start, _length, _vptr)		\
	_bt_bitfield_read_be(_ptr, type, _start, _length, _vptr)

#define bt_bitfield_read_le(_ptr, type, _start, _length, _vptr)		\
	_bt_bitfield_read_le(_ptr, unsigned char, _start, _length, _vptr)

#define bt_bitfield_read_be(_ptr, type, _start, _length, _vptr)		\
	_bt_bitfield_read_be(_ptr, type, _start, _length, _vptr)

#else /* (BYTE_ORDER == PDP_ENDIAN) */

#error "Byte order not supported"

#endif

#endif /* _BABELTRACE_BITFIELD_H */
