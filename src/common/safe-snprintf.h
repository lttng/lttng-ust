/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 */

#ifndef _UST_COMMON_SAFE_SNPRINTF_H
#define _UST_COMMON_SAFE_SNPRINTF_H

#include <stdarg.h>
#include <stddef.h>

int ust_safe_vsnprintf(char *str, size_t n, const char *fmt, va_list ap)
	__attribute__((visibility("hidden")));

int ust_safe_snprintf(char *str, size_t n, const char *fmt, ...)
	__attribute__((visibility("hidden")))
	__attribute__((format(printf, 3, 4)));

#endif /* _UST_COMMON_SAFE_SNPRINTF_H */
