# SPDX-License-Identifier: GPL-2.0-or-later WITH LicenseRef-Autoconf-exception-macro
# SPDX-FileCopyrightText: 2021 Michael Jeanson <mjeanson@efficios.com>
#
# SYNOPSIS
#
# AE_IF_IN_GIT_REPO(ACTION-IF-TRUE, [ACTION-IF-FALSE])
#
# DESCRIPTION
#
# Check if we are building from the git repository.
#
# The cache variable for this test is `ae_cv_in_git_repo`.
#
# ---------------------------------------------------------------------------

#serial 3

AC_DEFUN([AE_IF_IN_GIT_REPO], [
  AC_CACHE_VAL([ae_cv_in_git_repo], [

      dnl We're in the Git repository; the `bootstrap` file
      dnl is not distributed in tarballs
      AS_IF([test -f "$srcdir/bootstrap"],
        [ae_cv_in_git_repo=yes],
        [ae_cv_in_git_repo=no])
  ])

  AS_IF([test "x$ae_cv_in_git_repo" = "xyes"], [dnl
    $1
  ], [:
    $2
  ])
])
