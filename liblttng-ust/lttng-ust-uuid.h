#ifndef _LTTNG_UST_UUID_H
#define _LTTNG_UST_UUID_H

/*
 * Copyright (C) 2011   Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

#include <config.h>
#include <lttng/ust-events.h> /* For LTTNG_UST_UUID_LEN */
/*
 * Includes final \0.
 */
#define LTTNG_UST_UUID_STR_LEN		37

#ifdef LTTNG_UST_HAVE_LIBUUID
#include <uuid/uuid.h>

static inline
int lttng_ust_uuid_generate(unsigned char *uuid_out)
{
	uuid_generate(uuid_out);
	return 0;
}

#elif defined(LTTNG_UST_HAVE_LIBC_UUID)
#include <uuid.h>
#include <stdint.h>

static inline
int lttng_ust_uuid_generate(unsigned char *uuid_out)
{
	uint32_t status;

	uuid_create(uuid_out, &status);
	if (status == uuid_s_ok)
		return 0;
	else
		return -1;
}

#else
#error "LTTng-UST needs to have a UUID generator configured."
#endif

#endif /* _LTTNG_UST_UUID_H */
