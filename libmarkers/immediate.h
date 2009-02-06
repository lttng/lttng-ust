#ifndef _LINUX_IMMEDIATE_H
#define _LINUX_IMMEDIATE_H

/*
 * Immediate values, can be updated at runtime and save cache lines.
 *
 * (C) Copyright 2007 Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 *
 * This file is released under the GPLv2.
 * See the file COPYING for more details.
 */

#ifdef USE_IMMEDIATE

#include <asm/immediate.h>

/**
 * imv_set - set immediate variable (with locking)
 * @name: immediate value name
 * @i: required value
 *
 * Sets the value of @name, taking the module_mutex if required by
 * the architecture.
 */
#define imv_set(name, i)						\
	do {								\
		name##__imv = (i);					\
		core_imv_update();					\
		module_imv_update();					\
	} while (0)

/*
 * Internal update functions.
 */
extern void core_imv_update(void);
extern void imv_update_range(const struct __imv *begin,
	const struct __imv *end);
extern void imv_unref_core_init(void);
extern void imv_unref(struct __imv *begin, struct __imv *end, void *start,
		unsigned long size);

#else

/*
 * Generic immediate values: a simple, standard, memory load.
 */

/**
 * imv_read - read immediate variable
 * @name: immediate value name
 *
 * Reads the value of @name.
 */
#define imv_read(name)			_imv_read(name)

/**
 * imv_set - set immediate variable (with locking)
 * @name: immediate value name
 * @i: required value
 *
 * Sets the value of @name, taking the module_mutex if required by
 * the architecture.
 */
#define imv_set(name, i)		(name##__imv = (i))

static inline void core_imv_update(void) { }
static inline void imv_unref_core_init(void) { }

#endif

#define DECLARE_IMV(type, name) extern __typeof__(type) name##__imv
#define DEFINE_IMV(type, name)  __typeof__(type) name##__imv

#define EXPORT_IMV_SYMBOL(name) EXPORT_SYMBOL(name##__imv)
#define EXPORT_IMV_SYMBOL_GPL(name) EXPORT_SYMBOL_GPL(name##__imv)

/**
 * _imv_read - Read immediate value with standard memory load.
 * @name: immediate value name
 *
 * Force a data read of the immediate value instead of the immediate value
 * based mechanism. Useful for __init and __exit section data read.
 */
#define _imv_read(name)		(name##__imv)

#endif
