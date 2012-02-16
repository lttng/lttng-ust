/*
 * Copyright (C) 2011-2012  Matthew Khouzam <matthew.khouzam@ericsson.com>
 * Copyright (C) 2012  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program for any
 * purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is
 * granted, provided the above notices are retained, and a notice that
 * the code was modified is included with the above copyright notice.
 */
#include <unistd.h>

#include "sample_tracepoint.h"
int main(int argc, char **argv)
{
	int i = 0;

	for (i = 0; i < 100000; i++) {
		tracepoint(sample_tracepoint, message,  "Hello World\n");
		usleep(1);
	}
	return 0;
}
