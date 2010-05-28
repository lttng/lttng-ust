#!/bin/bash
#
# Copyright 2010 Ericsson AB
#
#    This file is part of LTTng-UST.
#
#    LTTng-UST is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    LTTng-UST is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with LTTng-UST.  If not, see <http://www.gnu.org/licenses/>.

function starttest() {

	echo "------------------------------------"
	echo "Starting test: $1"
	echo "------------------------------------"
}

function check_trace_logs() {
	TRACE=$1

	for f in $(ls $1/*.log); do
		NLINES=$(egrep "Warning|Error" $f | wc -l)
		if [ "$NLINES" -ne "0" ]; then
			fail "Errors/warnings found in $f"
			return 1;
		fi
	done
	pass "$f was consistent"
	return 0;
}


function trace_matches() {

    RUNLTTV=~/devel/lttv/runlttv

    if [ ! -x "$RUNLTTV" ]; then
	echo "$0: $RUNLTTV not executable. Edit \$RUNLTTV to point to your lttv source directory." >/dev/stderr
	exit 1;
    fi

    while getopts ":n:N:" options; do
	case "$options" in
	    n) expected_count=$OPTARG;;
	    N) name=$OPTARG;;
	    *) echo "Invalid option to trace_matches"
		exit 1;;
	esac
    done
    shift $(($OPTIND - 1))

    pattern=$1
    if [ -z "$pattern" ]; then
	error "no pattern specified"
	usage
	exit 1
    fi

    if [ -z "$2" ]; then
	error "no trace directory specified"
	return 1
    fi
    traces=$(find "$2" -mindepth 1 -maxdepth 1 -type d)

    cnt=$($RUNLTTV -m text "$traces" | grep "$pattern" | wc -l)
    if [ -z "$expected_count" ]; then
	if [ "$cnt" -eq "0" ]; then
	    fail "Did not find at least one instance of $name in trace"
	    return 1
	else
	    pass "Found at least one instance of $name in trace."
	    return 0
	fi
    else
	if [ "$cnt" -ne "$expected_count" ]; then
	    fail "Found $cnt instances of $name in trace, expected $expected_count"
	    return 1
	else
	    pass "Found $cnt instances of $name in trace."
	    return 0
	fi
    fi
}
