/* Copyright (C) 2011 Nils Carlson
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

/* This test generates a single event and exits.
 */

#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ust/marker.h>

int main(int argc, char *argv[])
{
	int suicide = 0;

	if (argc > 1 && !strcmp(argv[1], "suicide")) {
		suicide = 1;
	}

	ust_marker(fast, "%d", 0xf330);

	if (suicide) {
		kill(getpid(), SIGKILL);
	}
	return 0;
}
