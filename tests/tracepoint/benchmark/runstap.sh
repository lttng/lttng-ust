#!/bin/sh

#SystemTAP benchmark

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
