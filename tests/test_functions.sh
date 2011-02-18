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
    local OPTIND=

    #Get a textdump command
    # if RUNLTTV is defined try to use it
    # if LTTV variable is defined try to use it
    # try to find lttv in the path
    # try to find runlttv in std paths (devel/lttv/runlttv and ust/../lttv/runlttv

    if [ ! -d "$RUNLTTV" -a -x "$RUNLTTV" ]; then
	LTTV_TEXTDUMP_CMD="$RUNLTTV -m text "
	LTTV_TRACE_PREFIX=""
	
    elif [ -d "$RUNLTTV" -a -x "$RUNLTTV/runlttv" ]; then 
	LTTV_TEXTDUMP_CMD="$RUNLTTV/runlttv -m text "
	LTTV_TRACE_PREFIX=""

    elif [ ! -d "$LTTV" -a -x "$LTTV" ]; then
	LTTV_TEXTDUMP_CMD="$LTTV -m textDump "
	LTTV_TRACE_PREFIX="-t"

    elif [ -d "$LTTV" -a -x "$LTTV/lttv" ]; then
	LTTV_TEXTDUMP_CMD="$LTTV/lttv -m textDump "
	LTTV_TRACE_PREFIX="-t"
	
    elif [ -x "$(which lttv.real)" ]; then
	LTTV_TEXTDUMP_CMD="$(which lttv.real) -m textDump ";
	LTTV_TRACE_PREFIX="-t"
	
    elif [ -x "~/devel/lttv/runlttv" ]; then
	LTTV_TEXTDUMP_CMD="~/devel/lttv/runlttv -m text ";
	LTTV_TRACE_PREFIX=""

    elif [ -x "$(dirname `readlink -f $0`)/../../lttv/runlttv" ]; then
	LTTV_TEXTDUMP_CMD="$(dirname `readlink -f $0`)/../../lttv/runlttv -m text "
	LTTV_TRACE_PREFIX=""

    else
	echo "$0: No lttv found. Edit \$RUNLTTV to point to your lttv source directory or \$LTTV to you lttv executable." >/dev/stderr
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
    lttv_trace_cmd=$LTTV_TEXTDUMP_CMD
    for trace in $traces; do
	lttv_trace_cmd="$lttv_trace_cmd $LTTV_TRACE_PREFIX $trace"
    done
    cnt=$($lttv_trace_cmd | grep "$pattern" | wc -l)
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
