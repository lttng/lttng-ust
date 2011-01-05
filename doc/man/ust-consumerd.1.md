ust-consumerd(1) -- a daemon that collects trace data and writes it to the disk
======================================================================

## SYNOPSIS

`ust-consumerd` [<options>]

## DESCRIPTION

`ust-consumerd` is a program that collects trace data and writes it to the disk.

## OPTIONS

These programs follow the usual GNU command line syntax, with long options
starting with two dashes(`-'). A summary of options is included below.

  * `-h`, `--help`:
    Show summary of options.

  * `-o` <DIR>:
    Specify the directory where to output the traces.

  * `-s` <PATH>:
    Specify the path to use for the daemon socket.

  * `-d`:
    Start as a daemon.

  * `-p`, `--pidfile`=<FILE>:
    Write the PID in this file (when using -d).

  * `-V`, `--version`:
    Show version of program.

## SEE ALSO

ustctl(1), usttrace(1)

## AUTHOR

`ust-consumerd` was written by Pierre-Marc Fournier.

This manual page was written by Jon Bernard &lt;jbernard@debian.org&gt;, for
the Debian project (and may be used by others).
