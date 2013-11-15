#!/bin/sh

# Copyright (C) 2010 David Goulet <david.goulet@polymtl.ca>
# Copyright (C) 2010 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# SystemTAP benchmark

REPORT=/tmp/testreport

rm $REPORT

echo "Userspace tracing scalability test report" |tee >> $REPORT

for nr_threads in 1 2 4 8; do
	echo "" | tee >> $REPORT
	echo Number of threads: $nr_threads | tee >> $REPORT
	echo "* Baseline" | tee >> $REPORT

	killall stapio
	sleep 3

	sync
	/usr/bin/time -o /tmp/testlog ./.libs/tracepoint_benchmark ${nr_threads}
	cat /tmp/testlog >> $REPORT

	echo "* Flight recorder" | tee >> $REPORT
	#For flight recorder
	#stap testutrace.stp -F

	#Writing to disk
	stap testutrace.stp -o /tmp/stapconsole-$nr_threads &

	sleep 2
	sync
	/usr/bin/time -o /tmp/testlog ./.libs/tracepoint_benchmark ${nr_threads}
	cat /tmp/testlog >> $REPORT
done

cat /tmp/testreport
