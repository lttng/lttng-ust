#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <stdio.h>

#include "marker.h"

void *(*plibc_malloc)(size_t size) = NULL;

void *malloc(size_t size)
{
	if(plibc_malloc == NULL) {
		plibc_malloc = dlsym(RTLD_NEXT, "malloc");
		if(plibc_malloc == NULL) {
			fprintf(stderr, "mallocwrap: unable to find malloc\n");
			return NULL;
		}
	}

	trace_mark(ust, malloc, "%d", (int)size);

	fprintf(stderr, "mallocating size %d\n", size);
	return plibc_malloc(size);
}

MARKER_LIB
