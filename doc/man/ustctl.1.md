ustctl(1) -- a program to control the tracing of userspace applications
=======================================================================

## SYNOPSIS

`ustctl` [<command>] [<PIDs>]...

## DESCRIPTION

`ustctl` is a program to control the tracing of userspace applications. It can
list markers, start the tracing, stop the tracing, enable/disable markers, etc.

## OPTIONS

These programs follow the usual GNU command line syntax, with long options
starting with two dashes(`-'). A summary of options is included below.

  * `-h`, `--help`:
    Show summary of options.

  * `--create-trace`:
    Create trace.

  * `--alloc-trace`:
    Allocate trace.

  * `--start-trace`:
    Start tracing.

  * `--stop-trace`:
    Stop tracing.

  * `--destroy-trace`:
    Destroy the trace.

  * `--set-subbuf-size` <CHANNEL>/<bytes>:
    Set the size of subbuffers in CHANNEL.

  * `--set-subbuf-num` <CHANNEL>:
    Set the number of subbuffers per buffer for CHANNEL. Must be a power of 2.

  * `--set-sock-path`:
    Set the path of the daemon socket.

  * `--get-subbuf-size` <CHANNEL>:
    Print the size of subbuffers per buffer for CHANNEL.

  * `--get-subbuf-num` <CHANNEL>:
    Print the number of subbuffers per buffer for CHANNEL.

  * `--get-sock-path`:
    Get the path of the daemon socket.

  * `--enable-marker` <CHANNEL>/<MARKER>:
    Enable a marker.

  * `--disable-marker` <CHANNEL>/<MARKER>:
    Disable a marker.

  * `--list-markers`:
    List the markers of the process, their state and format string.

  * `--force-switch`:
    Force a subbuffer switch. This will flush all the data currently held.

## LIFE CYCLE OF A TRACE

Typically, the first step is to enable markers with `--enable-marker`. An
enabled marker generates an event when the control flow passes over it
(assuming the trace is recording). A disabled marker produces nothing. Enabling
and disabling markers may however be done at any point, including while the
trace is being recorded.

In order to record events, a trace is first created with `--create-trace`. At
this point, the subbuffer count and size may be changed with `--set-subbuf-num`
and `--set-subbuf-size`.

Afterward, the trace may be allocated with `--alloc-trace`. This allocates the
buffers in memory, so once this is done, the subbuffer size and count can not
be changed. Trace allocation also causes the daemon to connect to the trace
buffers and wait for data to arrive. Explicit allocation is optional, as it is
done automatically at trace start.

The trace may then be started with `--start-trace`. This results in events
being recorded in the buffer. The daemon automatically collects these events.

The trace may be stopped with `--stop-trace`, either definitely after all the
wanted information is collected, or temporarily, before being started again
with `--start-trace`. This results in effectively "pausing" the recording.

Finally, when `--destroy-trace` is used, the trace buffers are unallocated.
However, the memory may not be effectively freed until the daemon finishes to
collect them.

## STRUCTURE OF A TRACE

Each instrumentation point that is added in a program is associated to a
channel.

Trace events are put in buffers. There is one buffer per channel, per cpu.
For example, on a system with 4 cores and tracing an application with 3
channels, there will be 12 buffers in total. The content of each of these
buffers is put in a distinct file in the trace directory. For example, the
`metadata_2` file contains the data that was extracted from the buffer that
contained the events from the metadata channel and having occurred on cpu 2.

In memory, each buffer is divided in subbuffers. Subbuffers are equally-sized,
contiguous parts of a buffer. The size of a buffer is equal to the number of
subbuffers it contains times the size of each subbuffer. When a subbuffer is
full, it is collected by the daemon while the others are filled. If, however,
the buffer size is too small, buffer overflows may occur and result in event
loss. By default, the number of subbuffers per buffer is 2. Subbuffer size
for a given channel may be chosen with `--set-subbuf-size` while the subbuffer
count is set with `--set-subbuf-num`.

## SEE ALSO

usttrace(1), ustd(1)

## AUTHOR

`ustctl` was written by Pierre-Marc Fournier.

This manual page was written by Jon Bernard &lt;jbernard@debian.org&gt;, for
the Debian project (and may be used by others). It was updated by Pierre-Marc
Fournier.
