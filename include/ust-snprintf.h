/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 */

#ifndef UST_SNPRINTF
#define UST_SNPRINTF

#include <stdarg.h>
#include <stddef.h>

extern int ust_safe_vsnprintf(char *str, size_t n, const char *fmt, va_list ap);
extern int ust_safe_snprintf(char *str, size_t n, const char *fmt, ...);

#endif /* UST_SNPRINTF */
