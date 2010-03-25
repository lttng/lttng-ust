ustctl(1) -- a program to control the tracing of userspace applications
=======================================================================

## SYNOPSIS

`ustctl` [<command>] [<PIDs>]...

## DESCRIPTION

`ustclt` is a program to control the tracing of userspace applications. It can
list markers, start the tracing, stop the tracing, enable/disable markers, etc.

## OPTIONS

These programs follow the usual GNU command line syntax, with long options
starting with two dashes(`-'). A summary of options is included below.

  * `-h`, `--help`:
    Show summary of options.

  * `--create-trace`:
    Create trace.

  * `--alloc-trace`:
    Alloc trace.

  * `--start-trace`:
    Start tracing.

  * `--stop-trace`:
    Stop tracing.

  * `--destroy-trace`:
    Destroy the trace.

  * `--set-subbuf-size` <CHANNEL>/<bytes>:
    Set the size of subbuffers per channel.

  * `--set-subbuf-num` <CHANNEL>:
    Set the number of subbuffers per channel.

  * `--get-subbuf-size` <CHANNEL>:
    Get the size of subbuffers per channel.

  * `--get-subbuf-num` <CHANNEL>:
    Get the number of subbuffers per channel.

  * `--enable-marker` <CHANNEL>/<MARKER>:
    Enable a marker.

  * `--disable-marker` <CHANNEL>/<MARKER>:
    Disable a marker.

  * `--list-markers`:
    List the markers of the process, their state and format string.

## AUTHOR

`ustctl` was written by Pierre-Marc Fournier.

This manual page was written by Jon Bernard &lt;jbernard@debian.org&gt;, for
the Debian project (and may be used by others).
