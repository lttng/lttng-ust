/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2021 Norbert Lange <nolange79@gmail.com>
 *
 * Shared helper macro for tracelog and tracef.
 */

#define LTTNG_UST_TRACELOG_VARARG(fmt, callback, ...) \
	do { \
		char local_buf[LTTNG_TRACE_PRINTF_BUFSIZE]; \
		char *alloc_buff = NULL, *msg = local_buf; \
		size_t len = 0; \
		va_list ap; \
\
		if (caa_unlikely(fmt[0] == '%' && fmt[1] == 's' && fmt[2] == '\0')) { \
			va_start(ap, fmt); \
			msg = va_arg(ap, char *); \
			va_end(ap); \
			len = strlen(msg); \
		} else { \
			size_t buflen = sizeof(local_buf); \
			int ret; \
\
			/* On-stack buffer attempt */ \
			va_start(ap, fmt); \
			ret = vsnprintf(msg, buflen, fmt, ap); \
			va_end(ap); \
			if (caa_unlikely(ret < 0)) \
				break; \
			len = (size_t)ret; \
\
			if (caa_unlikely(len >= sizeof(local_buf))) { \
				buflen = len + 1; \
				alloc_buff = (char *)malloc(buflen); \
				if (!alloc_buff) \
					goto end; \
				msg = alloc_buff; \
				va_start(ap, fmt); \
				ret = vsnprintf(msg, buflen, fmt, ap); \
				va_end(ap); \
				lttng_ust_runtime_bug_on(ret < 0 || (size_t)ret != buflen - 1); \
				len = (size_t)ret; \
			} \
		} \
\
		callback(__VA_ARGS__); \
end: \
		/* Don't call a potentially instrumented forbidden free needlessly. */ \
		if (caa_unlikely(alloc_buff)) \
			free(alloc_buff); \
	} while(0)

#define LTTNG_UST_TRACELOG_VALIST(fmt, ap, callback, ...) \
	do { \
		char local_buf[LTTNG_TRACE_PRINTF_BUFSIZE]; \
		char *alloc_buff = NULL, *msg = local_buf; \
		size_t len = 0; \
\
		if (caa_unlikely(fmt[0] == '%' && fmt[1] == 's' && fmt[2] == '\0')) { \
			msg = va_arg(ap, char *); \
			len = strlen(msg); \
		} else { \
			size_t buflen = sizeof(local_buf); \
			va_list ap2; \
			int ret; \
\
			va_copy(ap2, ap); \
			ret = vsnprintf(msg, buflen, fmt, ap2); \
			va_end(ap2); \
			if (caa_unlikely(ret < 0)) \
				break; \
			len = (size_t)ret; \
\
			if (caa_unlikely(len >= sizeof(local_buf))) { \
				buflen = len + 1; \
				alloc_buff = (char *)malloc(buflen); \
				if (!alloc_buff) \
					goto end; \
				msg = alloc_buff; \
				ret = vsnprintf(msg, buflen, fmt, ap); \
				lttng_ust_runtime_bug_on(ret < 0 || (size_t)ret != buflen - 1); \
				len = (size_t)ret; \
			} \
		} \
\
		callback(__VA_ARGS__); \
end: \
		/* Don't call a potentially instrumented forbidden free needlessly. */ \
		if (caa_unlikely(alloc_buff)) \
			free(alloc_buff); \
	} while (0)
