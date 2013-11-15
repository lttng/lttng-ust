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

# UST scalability test

REPORT=/tmp/testreport

rm $REPORT

echo "Userspace tracing scalability test report" |tee >> $REPORT

for nr_threads in 1 2 4 8; do
	echo "" | tee >> $REPORT
	echo Number of threads: $nr_threads | tee >> $REPORT
	echo "* Baseline" | tee >> $REPORT

	sync
	/usr/bin/time -o /tmp/testlog ./.libs/tracepoint_benchmark ${nr_threads}
	cat /tmp/testlog >> $REPORT

	#flight recorder, don't record trace to disk.
	export UST_AUTOCOLLECT=0
	export UST_OVERWRITE=1
	export UST_SUBBUF_NUM=16
	#default buffer size is 4k

	#Collect traces to disk
	#export UST_AUTOCOLLECT=1
	#export UST_OVERWRITE=0
	#export UST_SUBBUF_NUM=16
	#default buffer size is 4k

	echo "* Flight recorder" | tee >> $REPORT
	sync
	/usr/bin/time -o /tmp/testlog usttrace ./.libs/tracepoint_benchmark ${nr_threads}
	cat /tmp/testlog >> $REPORT
done

cat /tmp/testreport
