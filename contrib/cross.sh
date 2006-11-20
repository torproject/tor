#!/bin/bash
# $Id$
# Copyright 2006 Michael Mohr with modifications by Roger Dingledine
# See LICENSE for licensing information.

#######################################################################
#  Tor-cross: a tool to help cross-compile Tor
#
#  The purpose of a cross-compiler is to produce an executable for
#  one system (CPU) on another.  This is useful, for example, when
#  the target system does not have a native compiler available.
#  You might, for example, wish to cross-compile a program on your
#  host (the computer you're working on now) for a target such as
#  a router or handheld computer.
#
#  A number of environment variables must be set in order for this
#  script to work:
#        $PREFIX, $CROSSPATH, $HOST_TRIPLET, $HOST,
#        and (optionally) $BUILD
#  Please run the script for a description of each one.  If automated
#  builds are desired, the above variables can be exported at the top
#  of this script.
#
#  Recent releases of Tor include test programs in configure. Normally
#  this is a good thing, since it catches a number of problems.
#  However, this also presents a problem when cross compiling, since
#  you can't run binary images for the target system on the host.
#
#  Tor-cross assumes that you know what you're doing and removes a
#  number of checks known to cause problems with this process.
#  Note that this does not guarantee that the program will run or
#  even compile; it simply allows configure to generate the Makefiles.
#
#  Stripping the binaries should almost always be done for an
#  embedded environment where space is at an exacting premium.
#  However, the default is NOT to strip them since they are useful for
#  debugging.  If you do not plan to do any debugging and you
#  don't care about the debugging symbols, set $STRIP to "yes" before
#  running this script.
#
#  Tor-cross was written by Michael Mohr.  He can be contacted at
#  m(dot)mohr(at)laposte(dot)net.  Comments are appreciated, but
#  flames go to /dev/null.
#
#  The target with which this script is tested is little-endian
#  MIPS Linux, built on an Athlon-based Linux desktop.
#
#######################################################################

# disable the platform-specific tests in configure
export CROSS_COMPILE=yes

# for error conditions
EXITVAL=0

if [ ! -f autogen.sh ]
then
  echo "Please run this script from the root of the Tor distribution"
  exit -1
fi

if [ ! -f configure ]
then
  if [ -z $GEN_BUILD ]
  then
    echo "To automatically generate the build environment, set \$GEN_BUILD"
    echo "to yes; for example,"
    echo "	export GEN_BUILD=yes"
    EXITVAL=-1
  fi
fi

if [ -z $PREFIX ]
then
  echo "You must define \$PREFIX since you are cross-compiling."
  echo "Select a non-system location (i.e. /tmp/tor-cross):"
  echo "	export PREFIX=/tmp/tor-cross"
  EXITVAL=-1
fi

if [ -z $CROSSPATH ]
then
  echo "You must define the location of your cross-compiler's"
  echo "directory using \$CROSSPATH; for example,"
  echo "	export CROSSPATH=/opt/cross/staging_dir_mipsel/bin"
  EXITVAL=-1
fi

if [ -z $HOST_TRIPLET ]
then
  echo "You must define \$HOST_TRIPLET to continue.  For example,"
  echo "if you normally cross-compile applications using"
  echo "mipsel-linux-uclibc-gcc, you would set \$HOST_TRIPLET like so:"
  echo "	export HOST_TRIPLET=mipsel-linux-uclibc-"
  EXITVAL=-1
fi

if [ -z $HOST ]
then
  echo "You must specify a target processor with \$HOST; for example:"
  echo "	export HOST=mipsel-unknown-elf"
  EXITVAL=-1
fi

if [ -z $BUILD ]
then
  echo "You should specify the host machine's type with \$BUILD; for example:"
  echo "	export BUILD=i686-pc-linux-gnu"
  echo "If you wish to let configure autodetect the host, set \$BUILD to 'auto':"
  echo "	export BUILD=auto"
  EXITVAL=-1
fi

if [ ! -x $CROSSPATH/$HOST_TRIPLETgcc ]
then
  echo "The specified toolchain does not contain an executable C compiler."
  echo "Please double-check your settings and rerun cross.sh."
  EXITVAL=-1
fi

if [ $EXITVAL -ne 0 ]
then
  echo "Remember, you can hard-code these values in cross.sh if needed."
  exit $EXITVAL
fi

if [ ! -z $GEN_BUILD -a ! -f configure ]
then
  export NOCONF=yes
  ./autogen.sh
fi

# clean up any existing object files
if [ -f src/or/tor ]
then
  make clean
fi

# Set up the build environment and try to run configure
export PATH=$PATH:$CROSSPATH
export RANLIB=${HOST_TRIPLET}ranlib
export CC=${HOST_TRIPLET}gcc

if [ $BUILD == "auto" ]
then
  ./configure \
	--enable-debug \
	--enable-eventdns \
	--prefix=$PREFIX \
	--host=$HOST
else
  ./configure \
	--enable-debug \
	--enable-eventdns \
	--prefix=$PREFIX \
	--host=$HOST \
	--build=$BUILD
fi

# has a problem occurred?
if [ $? -ne 0 ]
then
  echo ""
  echo "A problem has been detected with configure."
  echo "Please check the output above and rerun cross.sh"
  echo ""
  exit -1
fi

# Now we're cookin'

make

# has a problem occurred?
if [ $? -ne 0 ]
then
  echo ""
  echo "A problem has been detected with make."
  echo "Please check the output above and rerun make."
  echo ""
  exit -1
fi

# if $STRIP has length (i.e. STRIP=yes), strip the binaries
if [ ! -z $STRIP ]
then
${HOST_TRIPLET}strip \
	src/or/tor \
	src/or/test \
	src/tools/tor-resolve
fi

echo ""
echo "Tor should be compiled at this point.  Now run 'make install' to"
echo "install to $PREFIX"
echo ""
