dnl $Id$
dnl Helper macros for Tor configure.in
dnl Copyright (c) 2001-2004, Roger Dingledine
dnl Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson
dnl See LICENSE for licensing information

dnl TODO
dnl  - Stop requiring gethostbyname_r entirely when we're building with
dnl    eventdns?
dnl  - Remove redundant event.h check.
dnl  - Make the "no longe strictly accurate" message accurate.
dnl  - Tell the user what -dev package to install based on OS.
dnl  - Detect correct version of library.
dnl  - After merge:
dnl     Run autoupdate

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

dnl Look for a library, and its associated includes, and how to link
dnl against it.
dnl 
dnl TOR_SEARCH_LIBRARY(libname, withlocation, linkargs, headers, prototype,
dnl                    code, optionname, searchextra)

AC_DEFUN([TOR_SEARCH_LIBRARY], [
tor_saved_LIBS="$LIBS"
tor_saved_LDFLAGS="$LDFLAGS"
tor_saved_CPPFLAGS="$CPPFLAGS"
AC_CACHE_CHECK([for $1 directory], tor_cv_library_$1_dir, [
  tor_$1_dir_found=no
  tor_$1_any_linkable=no
  
  for tor_trydir in "$2" "(system)" "$prefix" /usr/local /usr/pkg $8; do
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

    # Can we link against (but not necessarily compile) the binary?
    AC_LINK_IFELSE(AC_LANG_PROGRAM([$5], [$6]),
                   [linkable=yes], [linkable=no])

    if test $linkable = yes; then
      tor_$1_any_linkable=yes
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
      AC_MSG_ERROR([Could not find a linkable $1.  You can specify an explicit path using $7])
    else
      AC_MSG_ERROR([We found the libraries for $1, but we could not find the C header files.  You may need to install a devel package.])
    fi
  fi

  LDFLAGS="$tor_saved_LDFLAGS"
  LIBS="$tor_saved_LIBS $3"
  CPPFLAGS="$tor_saved_CPPFLAGS"
]) dnl end cache check

LIBS="$LIBS $3"
if test $tor_cv_library_$1_dir != "(system)"; then
   TOR_EXTEND_CODEPATH($tor_cv_library_$1_dir)
fi

if test -z "$CROSS_COMPILE"; then
  AC_CACHE_CHECK([whether we need extra options to link $1],
                 tor_cv_library_$1_linker_option, [
   tor_saved_LDFLAGS="$LDFLAGS"
   tor_trydir="$tor_cv_library_$1_dir"
   runs=no
   linked_with=nothing
   for tor_tryextra in "(none)" "-Wl,-R$tor_trydir" "-R$tor_trydir" \
                       "-Wl,-rpath,$le_libdir" ; do
     if test "$tor_tryextra" = "(none)"; then
       LDFLAGS="$saved_LDFLAGS"
     else
       LDFLAGS="$tor_tryextra $saved_LDFLAGS"
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
  ]) dnl check for extra options.

  if test "$tor_cv_library_$1_linker_option" != "(none)" ; then
   LDFLAGS="$tor_cv_library_$1_linker_option $LDFLAGS"
  fi
fi # cross-compile

]) dnl end defun

#XXXX Check for right version
#XXXX accept list of search paths as options
