dnl $Id$
dnl Helper macros for Tor configure.in
dnl Copyright (c) 2001-2004, Roger Dingledine
dnl Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson
dnl See LICENSE for licensing information

AC_DEFUN([TOR_EXTEND_CODEPATH],
[
  if test -d "$1/lib"; then
    LDFLAGS="-L$1/lib $LDFLAGS"
  else
    LDFLAGS="-L$1 $LDFLAGS"
  fi
  if test -d "$1/include"; then
    CPPFLAGS="-I$1/include $CPPFLAGS"
  else
    CPPFLAGS="-I$1 $CPPFLAGS"
  fi
])

AC_DEFUN([TOR_DEFINE_CODEPATH],
[
  if test x$1 = "x(system)"; then
    TOR_LDFLAGS_$2=""
    TOR_CPPFLAGS_$2=""
  else
   if test -d "$1/lib"; then
     TOR_LDFLAGS_$2="-L$1/lib"
   else
     TOR_LDFLAGS_$2="-L$1"
   fi
   if test -d "$1/include"; then
     TOR_CPPFLAGS_$2="-I$1/include"
   else
     TOR_CPPFLAGS_$2="-I$1"
   fi
  fi
  AC_SUBST(TOR_CPPFLAGS_$2)
  AC_SUBST(TOR_LDFLAGS_$2)
])

dnl 1:libname
AC_DEFUN([TOR_WARN_MISSING_LIB], [
h=""
if test x$2 = xdevpkg; then
  h=" headers for"
fi
if test -f /etc/debian_version -a x"$tor_$1_$2_debian" != x; then
  AC_WARN([On Debian, you can install$h $1 using "apt-get install $tor_$1_$2_debian"])
fi
if test -f /etc/fedora-release -a x"$tor_$1_$2_redhat" != x; then
  AC_WARN([On Fedora Core, you can install$h $1 using "yum install $tor_$1_$2_redhat"])
else
  if test -f /etc/redhat-release -a x"$tor_$1_$2_redhat" != x; then
    AC_WARN([On most Redhat-based systems, you can get$h $1 by installing the $tor_$1_$2_redhat" RPM package])
  fi
fi
])

dnl Look for a library, and its associated includes, and how to link
dnl against it.
dnl
dnl TOR_SEARCH_LIBRARY(1:libname, 2:IGNORED, 3:linkargs, 4:headers,
dnl                    5:prototype,
dnl                    6:code, 7:optionname, 8:searchextra)
AC_DEFUN([TOR_SEARCH_LIBRARY], [
try$1dir=""
AC_ARG_WITH($1-dir,
  [  --with-$1-dir=PATH    Specify path to $1 installation ],
  [
     if test x$withval != xno ; then
        try$1dir="$withval"
     fi
  ])
tor_saved_LIBS="$LIBS"
tor_saved_LDFLAGS="$LDFLAGS"
tor_saved_CPPFLAGS="$CPPFLAGS"
AC_CACHE_CHECK([for $1 directory], tor_cv_library_$1_dir, [
  tor_$1_dir_found=no
  tor_$1_any_linkable=no

  for tor_trydir in "$try$1dir" "(system)" "$prefix" /usr/local /usr/pkg $8; do
    LDFLAGS="$tor_saved_LDFLAGS"
    LIBS="$tor_saved_LIBS $3"
    CPPFLAGS="$tor_saved_CPPFLAGS"

    if test -z "$tor_trydir" ; then
      continue;
    fi

    # Skip the directory if it isn't there.
    if test ! -d "$tor_trydir" -a "$tor_trydir" != "(system)"; then
      continue;
    fi

    # If this isn't blank, try adding the directory (or appropriate
    # include/libs subdirectories) to the command line.
    if test "$tor_trydir" != "(system)"; then
      TOR_EXTEND_CODEPATH($tor_trydir)
    fi

    # Can we link against (but not necessarily run, or find the headers for)
    # the binary?
    AC_LINK_IFELSE(AC_LANG_PROGRAM([$5], [$6]),
                   [linkable=yes], [linkable=no])

    if test $linkable = yes; then
      tor_$1_any_linkable=yes
      # Okay, we can link against it.  Can we find the headers?
      AC_COMPILE_IFELSE(AC_LANG_PROGRAM([$4], [$6]),
                        [buildable=yes], [buildable=no])
      if test $buildable = yes; then
         tor_cv_library_$1_dir=$tor_trydir
         tor_$1_dir_found=yes
         break
      fi
    fi
  done

  if test $tor_$1_dir_found = no; then
    if test $tor_$1_any_linkable = no ; then
      AC_MSG_WARN([Could not find a linkable $1.  If you have it installed somewhere unusal, you can specify an explicit path using $7])
      TOR_WARN_MISSING_LIB($1, pkg)
      AC_MSG_ERROR([Missing libraries; unable to proceed.])
    else
      AC_MSG_WARN([We found the libraries for $1, but we could not find the C header files.  You may need to install a devel package.])
      TOR_WARN_MISSING_LIB($1, devpkg)
      AC_MSG_ERROR([Missing headers; unable to proceed.])
    fi
  fi

  LDFLAGS="$tor_saved_LDFLAGS"
  LIBS="$tor_saved_LIBS"
  CPPFLAGS="$tor_saved_CPPFLAGS"
]) dnl end cache check

LIBS="$LIBS $3"
if test $tor_cv_library_$1_dir != "(system)"; then
   TOR_EXTEND_CODEPATH($tor_cv_library_$1_dir)
fi

TOR_DEFINE_CODEPATH($tor_cv_library_$1_dir, $1)

if test -z "$CROSS_COMPILE"; then
  AC_CACHE_CHECK([whether we need extra options to link $1],
                 tor_cv_library_$1_linker_option, [
   orig_LDFLAGS="$LDFLAGS"
   runs=no
   linked_with=nothing
   if test -d "$tor_cv_library_$1_dir/lib"; then
     tor_trydir="$tor_cv_library_$1_dir/lib"
   else
     tor_trydir="$tor_cv_library_$1_dir"
   fi
   for tor_tryextra in "(none)" "-Wl,-R$tor_trydir" "-R$tor_trydir" \
                       "-Wl,-rpath,$tor_trydir" ; do
     if test "$tor_tryextra" = "(none)"; then
       LDFLAGS="$orig_LDFLAGS"
     else
       LDFLAGS="$tor_tryextra $orig_LDFLAGS"
     fi
     AC_RUN_IFELSE(AC_LANG_PROGRAM([$5], [$6]),
                   [runnable=yes], [runnable=no])
     if test "$runnable" = yes; then
        tor_cv_library_$1_linker_option=$tor_tryextra
        break
     fi
   done

   if test "$runnable" = no; then
     AC_MSG_ERROR([Found linkable $1 in $tor_cv_library_$1_dir, but it does not seem to run, even with -R. Maybe specify another using $7}])
   fi
   LDFLAGS="$orig_LDFLAGS"
  ]) dnl end cache check check for extra options.

  if test "$tor_cv_library_$1_linker_option" != "(none)" ; then
    TOR_LDFLAGS_$1="$TOR_LDFLAGS_$1 $tor_cv_library_$1_linker_option"
  fi
fi # cross-compile

LIBS="$tor_saved_LIBS"
LDFLAGS="$tor_saved_LDFLAGS"
CPPFLAGS="$tor_saved_CPPFLAGS"

]) dnl end defun

