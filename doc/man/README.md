LTTng-UST man pages
===================

This directory contains the sources of the LTTng-UST man pages.

LTTng-UST man pages are written in
[AsciiDoc](http://www.methods.co.nz/asciidoc/), and then converted to
DocBook (XML) using the `asciidoc` command, and finally to troff using
the appropriate DocBook XSL stylesheet (using the `xmlto` command).


Custom XSL stylesheets
----------------------

There are a few custom XSL stylesheets applied for customizing the
generated man pages in the `xsl` directory.


Macros
------

AsciiDoc is configured with `asciidoc.conf` which contains a few
macro definitions used everywhere in the man page sources.


### `man`

The `man` macro is used to specify a reference to another man page.
Using the provided `asciidoc.conf` configuration file, the man page
name is rendered in bold and the section is normal.

Usage example: `man:lttng-enable-channel(1)`, `man:dlopen(3)`


### `option`

The option macro is used to write a command-line option which is
**defined in the same man page**.

Usage example: `option:--output`, `option:--verbose`


### `nloption`

Command-line option generating no link. This is used when writing
about an option which is **not defined in the same man page**.

Usage example: `nloption:-finstrument-functions`


### `not`

The `:not:` macro is used to emphasize on _not_.


Includes
--------

  * `common-authors.txt`: common authors section of the LTTng-UST
    project. Only use this for man pages which describe
    a command/library/function written by the main authors of LTTng-UST.
  * `common-copyright.txt`: common copyrights section of the LTTng-UST
    project. Only use this for man pages which describe
    a command/library/function having the common LTTng-UST license.
  * `common-footer.txt`: common footer for all man pages. This goes
    before the copyrights section.
  * `log-levels.txt`: definition list of LTTng-UST log levels.
  * `tracef-tracelog-limitations.txt`: limitations that apply to both
    the `tracef(3)` and `tracelog(3)` man pages.


Convention
----------

Please follow those rules when updating the current man pages or writing
new ones:

  * Always use macros when possible (man page references, command-line
    options, _not_, etc.).
  * Use callouts with the `term` role for command-line examples.
  * Use a verse, possibly with the `term` role, in the synopsis section.
  * Always refer to _long_ options in the text.
  * Use the `option:--option='PARAM'` format (with `=`) when providing a
    parameter to long options.
  * Prefer writing _user space_ rather than _userspace_, _user-space_,
    or _user land_.
  * Write _file system_, not _filesystem_.
  * Prefer writing _use case_ rather than _use-case_ or _usecase_.
  * Write _log level_, not _loglevel_.
  * Write complete LTTng project names: _LTTng-modules_, _LTTng-UST_,
    and _LTTng-tools_, not _modules_, _UST_ and _tools_.
  * Prefer simple emphasis to strong emphasis for emphasizing text.
  * Try to stay behind the 72th column mark if possible, and behind the
    80th column otherwise.
  * Do not end directory paths with a forward slash (good:
    `include/trace/events`, bad: `include/trace/events/`).
  * Minimize the use of the future tense (_will_).
  * Use an active voice, and prefer using the second person (_you_) when
    referring to the user.
  * Avoid using Latin abbreviations (_e.g._, _i.e._, _etc._).
