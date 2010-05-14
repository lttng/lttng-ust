/* Copyright (C) 2010  Oussama El Mfadli, Alexis HallÃƒÂ©
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <dlfcn.h>
#include <stdio.h>
#include <ust/marker.h>

int main()
{
	int (*fptr)();

	trace_mark(ust, from_main_before_lib, "%s", "Event occured in the main program before"
						" the opening of the library\n");
	void *lib_handle = dlopen("libdummy.so", RTLD_LAZY);

	if (lib_handle == NULL) {
		fprintf(stderr, "%s\n", dlerror());
		return 1;
	}

	fptr = (int (*)())dlsym(lib_handle, "exported_function");

	if ( fptr == NULL) {
		fprintf(stderr, "%s\n", dlerror());
		return 1;
	}

	(*fptr)();
	dlclose(lib_handle);

	trace_mark(ust, from_main_after_lib,"%s", "Event occured in the main program after "
						"the library has been closed\n");

	return 0;
}
