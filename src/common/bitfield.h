/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2019 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_BITFIELD_H
#define _UST_COMMON_BITFIELD_H

#include <stdint.h>	/* C99 5.2.4.2 Numerical limits */
#include <limits.h>	/* C99 5.2.4.2 Numerical limits */
#include <stdbool.h>	/* C99 7.16 bool type */
#include <lttng/ust-endian.h>	/* Non-standard LTTNG_UST_BIG_ENDIAN, LTTNG_UST_LITTLE_ENDIAN, LTTNG_UST_BYTE_ORDER */

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

#define _bt_is_signed_type(type)	((type) -1 < (type) 1)

/*
 * Produce a build-time error if the condition `cond` is non-zero.
 * Evaluates as a size_t expression.
 */
#ifdef __cplusplus
#define _BT_BUILD_ASSERT(cond) ([]{static_assert((cond), "");}, 0)
#else
#define _BT_BUILD_ASSERT(cond)					\
	sizeof(struct { int f:(2 * !!(cond) - 1); })
#endif

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

#define _bt_bitfield_write_le(ptr, type, start, length, v)		\
do {									\
	__typeof__(v) _v = (v);					\
	type *_ptr = (void *) (ptr);					\
	unsigned long _start = (start), _length = (length);		\
	type _mask, _cmask;						\
	unsigned long _ts = sizeof(type) * CHAR_BIT; /* type size */	\
	unsigned long _start_unit, _end_unit, _this_unit;		\
	unsigned long _end, _cshift; /* _cshift is "complement shift" */ \
									\
	if (!_length)							\
		break;							\
									\
	_end = _start + _length;					\
	_start_unit = _start / _ts;					\
	_end_unit = (_end + (_ts - 1)) / _ts;				\
									\
	/* Trim v high bits */						\
	if (_length < sizeof(_v) * CHAR_BIT)				\
		_v &= _bt_make_mask(__typeof__(_v), _length);		\
									\
	/* We can now append v with a simple "or", shift it piece-wise */ \
	_this_unit = _start_unit;					\
	if (_start_unit == _end_unit - 1) {				\
		_mask = _bt_make_mask(type, _start % _ts);		\
		if (_end % _ts)						\
			_mask |= _bt_make_mask_complement(type, _end % _ts); \
		_cmask = _bt_lshift((type) (_v), _start % _ts);		\
		_cmask &= ~_mask;					\
		_ptr[_this_unit] &= _mask;				\
		_ptr[_this_unit] |= _cmask;				\
		break;							\
	}								\
	if (_start % _ts) {						\
		_cshift = _start % _ts;					\
		_mask = _bt_make_mask(type, _cshift);			\
		_cmask = _bt_lshift((type) (_v), _cshift);		\
		_cmask &= ~_mask;					\
		_ptr[_this_unit] &= _mask;				\
		_ptr[_this_unit] |= _cmask;				\
		_bt_safe_rshift(_v, _ts - _cshift);			\
		_start += _ts - _cshift;				\
		_this_unit++;						\
	}								\
	for (; _this_unit < _end_unit - 1; _this_unit++) {		\
		_ptr[_this_unit] = (type) _v;				\
		_bt_safe_rshift(_v, _ts);				\
		_start += _ts;						\
	}								\
	if (_end % _ts) {						\
		_mask = _bt_make_mask_complement(type, _end % _ts);	\
		_cmask = (type) _v;					\
		_cmask &= ~_mask;					\
		_ptr[_this_unit] &= _mask;				\
		_ptr[_this_unit] |= _cmask;				\
	} else								\
		_ptr[_this_unit] = (type) _v;				\
} while (0)

#define _bt_bitfield_write_be(ptr, type, start, length, v)		\
do {									\
	__typeof__(v) _v = (v);						\
	type *_ptr = (void *) (ptr);					\
	unsigned long _start = (start), _length = (length);		\
	type _mask, _cmask;						\
	unsigned long _ts = sizeof(type) * CHAR_BIT; /* type size */	\
	unsigned long _start_unit, _end_unit, _this_unit;		\
	unsigned long _end, _cshift; /* _cshift is "complement shift" */ \
									\
	if (!_length)							\
		break;							\
									\
	_end = _start + _length;					\
	_start_unit = _start / _ts;					\
	_end_unit = (_end + (_ts - 1)) / _ts;				\
									\
	/* Trim v high bits */						\
	if (_length < sizeof(_v) * CHAR_BIT)				\
		_v &= _bt_make_mask(__typeof__(_v), _length);		\
									\
	/* We can now append v with a simple "or", shift it piece-wise */ \
	_this_unit = _end_unit - 1;					\
	if (_start_unit == _end_unit - 1) {				\
		_mask = _bt_make_mask(type, (_ts - (_end % _ts)) % _ts); \
		if (_start % _ts)					\
			_mask |= _bt_make_mask_complement(type, _ts - (_start % _ts)); \
		_cmask = _bt_lshift((type) (_v), (_ts - (_end % _ts)) % _ts); \
		_cmask &= ~_mask;					\
		_ptr[_this_unit] &= _mask;				\
		_ptr[_this_unit] |= _cmask;				\
		break;							\
	}								\
	if (_end % _ts) {						\
		_cshift = _end % _ts;					\
		_mask = _bt_make_mask(type, _ts - _cshift);		\
		_cmask = _bt_lshift((type) (_v), _ts - _cshift);	\
		_cmask &= ~_mask;					\
		_ptr[_this_unit] &= _mask;				\
		_ptr[_this_unit] |= _cmask;				\
		_bt_safe_rshift(_v, _cshift);				\
		_end -= _cshift;					\
		_this_unit--;						\
	}								\
	for (; (long) _this_unit >= (long) _start_unit + 1; _this_unit--) { \
		_ptr[_this_unit] = (type) _v;				\
		_bt_safe_rshift(_v, _ts);				\
		_end -= _ts;						\
	}								\
	if (_start % _ts) {						\
		_mask = _bt_make_mask_complement(type, _ts - (_start % _ts)); \
		_cmask = (type) _v;					\
		_cmask &= ~_mask;					\
		_ptr[_this_unit] &= _mask;				\
		_ptr[_this_unit] |= _cmask;				\
	} else								\
		_ptr[_this_unit] = (type) _v;				\
} while (0)

/*
 * bt_bitfield_write - write integer to a bitfield in native endianness
 * bt_bitfield_write_le - write integer to a bitfield in little endian
 * bt_bitfield_write_be - write integer to a bitfield in big endian
 */

#if (LTTNG_UST_BYTE_ORDER == LTTNG_UST_LITTLE_ENDIAN)

#define bt_bitfield_write(ptr, type, start, length, v)			\
	_bt_bitfield_write_le(ptr, type, start, length, v)

#define bt_bitfield_write_le(ptr, type, start, length, v)		\
	_bt_bitfield_write_le(ptr, type, start, length, v)

#define bt_bitfield_write_be(ptr, type, start, length, v)		\
	_bt_bitfield_write_be(ptr, unsigned char, start, length, v)

#elif (LTTNG_UST_BYTE_ORDER == LTTNG_UST_BIG_ENDIAN)

#define bt_bitfield_write(ptr, type, start, length, v)			\
	_bt_bitfield_write_be(ptr, type, start, length, v)

#define bt_bitfield_write_le(ptr, type, start, length, v)		\
	_bt_bitfield_write_le(ptr, unsigned char, start, length, v)

#define bt_bitfield_write_be(ptr, type, start, length, v)		\
	_bt_bitfield_write_be(ptr, type, start, length, v)

#else /* (LTTNG_UST_BYTE_ORDER == PDP_ENDIAN) */

#error "Byte order not supported"

#endif

#define _bt_bitfield_read_le(ptr, type, start, length, vptr)		\
do {									\
	__typeof__(*(vptr)) *_vptr = (vptr);				\
	__typeof__(*_vptr) _v;						\
	type *_ptr = (type *) (ptr);					\
	unsigned long _start = (start), _length = (length);		\
	type _mask, _cmask;						\
	unsigned long _ts = sizeof(type) * CHAR_BIT; /* type size */	\
	unsigned long _start_unit, _end_unit, _this_unit;		\
	unsigned long _end, _cshift; /* _cshift is "complement shift" */ \
									\
	if (!_length) {							\
		*_vptr = 0;						\
		break;							\
	}								\
									\
	_end = _start + _length;					\
	_start_unit = _start / _ts;					\
	_end_unit = (_end + (_ts - 1)) / _ts;				\
									\
	_this_unit = _end_unit - 1;					\
	if (_bt_is_signed_type(__typeof__(_v))				\
	    && (_ptr[_this_unit] & _bt_lshift((type) 1, (_end % _ts ? _end % _ts : _ts) - 1))) \
		_v = ~(__typeof__(_v)) 0;				\
	else								\
		_v = 0;							\
	if (_start_unit == _end_unit - 1) {				\
		_cmask = _ptr[_this_unit];				\
		_cmask = _bt_rshift(_cmask, _start % _ts);		\
		if ((_end - _start) % _ts) {				\
			_mask = _bt_make_mask(type, _end - _start);	\
			_cmask &= _mask;				\
		}							\
		_bt_safe_lshift(_v, _end - _start);			\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _cmask); \
		*_vptr = _v;						\
		break;							\
	}								\
	if (_end % _ts) {						\
		_cshift = _end % _ts;					\
		_mask = _bt_make_mask(type, _cshift);			\
		_cmask = _ptr[_this_unit];				\
		_cmask &= _mask;					\
		_bt_safe_lshift(_v, _cshift);				\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _cmask); \
		_end -= _cshift;					\
		_this_unit--;						\
	}								\
	for (; (long) _this_unit >= (long) _start_unit + 1; _this_unit--) { \
		_bt_safe_lshift(_v, _ts);				\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _ptr[_this_unit]); \
		_end -= _ts;						\
	}								\
	if (_start % _ts) {						\
		_mask = _bt_make_mask(type, _ts - (_start % _ts));	\
		_cmask = _ptr[_this_unit];				\
		_cmask = _bt_rshift(_cmask, _start % _ts);		\
		_cmask &= _mask;					\
		_bt_safe_lshift(_v, _ts - (_start % _ts));		\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _cmask); \
	} else {							\
		_bt_safe_lshift(_v, _ts);				\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _ptr[_this_unit]); \
	}								\
	*_vptr = _v;							\
} while (0)

#define _bt_bitfield_read_be(ptr, type, start, length, vptr)		\
do {									\
	__typeof__(*(vptr)) *_vptr = (vptr);				\
	__typeof__(*_vptr) _v;						\
	type *_ptr = (void *) (ptr);					\
	unsigned long _start = (start), _length = (length);		\
	type _mask, _cmask;						\
	unsigned long _ts = sizeof(type) * CHAR_BIT; /* type size */	\
	unsigned long _start_unit, _end_unit, _this_unit;		\
	unsigned long _end, _cshift; /* _cshift is "complement shift" */ \
									\
	if (!_length) {							\
		*_vptr = 0;						\
		break;							\
	}								\
									\
	_end = _start + _length;					\
	_start_unit = _start / _ts;					\
	_end_unit = (_end + (_ts - 1)) / _ts;				\
									\
	_this_unit = _start_unit;					\
	if (_bt_is_signed_type(__typeof__(_v))				\
	    && (_ptr[_this_unit] & _bt_lshift((type) 1, _ts - (_start % _ts) - 1))) \
		_v = ~(__typeof__(_v)) 0;				\
	else								\
		_v = 0;							\
	if (_start_unit == _end_unit - 1) {				\
		_cmask = _ptr[_this_unit];				\
		_cmask = _bt_rshift(_cmask, (_ts - (_end % _ts)) % _ts); \
		if ((_end - _start) % _ts) {				\
			_mask = _bt_make_mask(type, _end - _start);	\
			_cmask &= _mask;				\
		}							\
		_bt_safe_lshift(_v, _end - _start);			\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _cmask); \
		*_vptr = _v;						\
		break;							\
	}								\
	if (_start % _ts) {						\
		_cshift = _start % _ts;					\
		_mask = _bt_make_mask(type, _ts - _cshift);		\
		_cmask = _ptr[_this_unit];				\
		_cmask &= _mask;					\
		_bt_safe_lshift(_v, _ts - _cshift);			\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _cmask); \
		_start += _ts - _cshift;				\
		_this_unit++;						\
	}								\
	for (; _this_unit < _end_unit - 1; _this_unit++) {		\
		_bt_safe_lshift(_v, _ts);				\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _ptr[_this_unit]); \
		_start += _ts;						\
	}								\
	if (_end % _ts) {						\
		_mask = _bt_make_mask(type, _end % _ts);		\
		_cmask = _ptr[_this_unit];				\
		_cmask = _bt_rshift(_cmask, _ts - (_end % _ts));	\
		_cmask &= _mask;					\
		_bt_safe_lshift(_v, _end % _ts);			\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _cmask); \
	} else {							\
		_bt_safe_lshift(_v, _ts);				\
		_v |= _bt_cast_value_to_unsigned_type(__typeof__(_v), _ptr[_this_unit]); \
	}								\
	*_vptr = _v;							\
} while (0)

/*
 * bt_bitfield_read - read integer from a bitfield in native endianness
 * bt_bitfield_read_le - read integer from a bitfield in little endian
 * bt_bitfield_read_be - read integer from a bitfield in big endian
 */

#if (LTTNG_UST_BYTE_ORDER == LTTNG_UST_LITTLE_ENDIAN)

#define bt_bitfield_read(ptr, type, start, length, vptr)		\
	_bt_bitfield_read_le(ptr, type, start, length, vptr)

#define bt_bitfield_read_le(ptr, type, start, length, vptr)		\
	_bt_bitfield_read_le(ptr, type, start, length, vptr)

#define bt_bitfield_read_be(ptr, type, start, length, vptr)		\
	_bt_bitfield_read_be(ptr, unsigned char, start, length, vptr)

#elif (LTTNG_UST_BYTE_ORDER == LTTNG_UST_BIG_ENDIAN)

#define bt_bitfield_read(ptr, type, start, length, vptr)		\
	_bt_bitfield_read_be(ptr, type, start, length, vptr)

#define bt_bitfield_read_le(ptr, type, start, length, vptr)		\
	_bt_bitfield_read_le(ptr, unsigned char, start, length, vptr)

#define bt_bitfield_read_be(ptr, type, start, length, vptr)		\
	_bt_bitfield_read_be(ptr, type, start, length, vptr)

#else /* (LTTNG_UST_BYTE_ORDER == PDP_ENDIAN) */

#error "Byte order not supported"

#endif

#endif /* _BABELTRACE_BITFIELD_H */
