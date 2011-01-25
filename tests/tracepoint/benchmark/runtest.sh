#!/bin/sh

#UST scalability test

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
