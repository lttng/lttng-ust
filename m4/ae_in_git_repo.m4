# SPDX-License-Identifier: MIT
#
# Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
#
# ae_in_git_repo.m4 -- Check if we are building from the git repo
#
# The cache variable for this test is `ae_cv_in_git_repo`.
#
# AE_IF_IN_GIT_REPO(ACTION-IF-TRUE, [ACTION-IF-FALSE])
# ---------------------------------------------------------------------------
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
  ], [: dnl
    $2
  ])
])
