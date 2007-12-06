#!/bin/bash
#
# tor-ctrl is a commandline tool for executing commands on a tor server via
# the controlport.  In order to get this to work, add "ControlPort 9051" and
# "CookieAuthentication 1" to your torrc and reload tor.  Or - if you want a
# fixed password - leave out "CookieAuthentication 1" and use the following
# line to create the appropriate HashedControlPassword entry for your torrc
# (you need to change yourpassword, of course):
#
# echo "HashedControlPassword $(tor --hash-password yourpassword | tail -n 1)"
#
# tor-ctrl will return 0 if it was successful and 1 if not, 2 will be returned
# if something (telnet, xxd) is missing.  4 will be returned if it executed
# several commands from a file.
#
# For setting the bandwidth for specific times of the day, I suggest calling
# tor-ctrl via cron, e.g.:
#
# 0 22 * * * /path/to/tor-ctrl -c "SETCONF bandwidthrate=1mb"
# 0 7 * * *  /path/to/tor-ctrl -c "SETCONF bandwidthrate=100kb"
#
# This would set the bandwidth to 100kb at 07:00 and to 1mb at 22:00.  You can
# use notations like 1mb, 1kb or the number of bytes.
#
# Many, many other things are possible, see
#              https://www.torproject.org/svn/trunk/doc/spec/control-spec.txt
#
# Copyright (c) 2007 by Stefan Behte
#
# tor-ctrl is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# tor-ctrl is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with tor-ctrl; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# Written by Stefan Behte
#
# Please send bugs, comments, wishes, thanks and success stories to:
# Stefan dot Behte at gmx dot net
#
# Also have a look at my page:
# http://ge.mine.nu/
#
# 2007-10-03: First version, only changing bandwidth possible.
# 2007-10-04: Renaming to "tor-ctrl", added a lot of functions, it's now a
#             general-purpose tool.
#             Added control_auth_cookie/controlpassword auth, getopts,
#             program checks, reading from file etc.

VERSION=v1
TORCTLIP=127.0.0.1
TORCTLPORT=9051
TOR_COOKIE="/var/lib/tor/data/control_auth_cookie"
SLEEP_AFTER_CMD=1
VERBOSE=0

usage()
{
cat <<EOF

tor-ctrl $VERSION by Stefan Behte (http://ge.mine.nu)
You should have a look at 
https://www.torproject.org/svn/trunk/doc/spec/control-spec.txt

usage: tor-ctrl [-switch] [variable]

       [-c] [command] = command to execute
                        notice: always "quote" your command

       [-f] [file]    = file to execute commands from
                        notice: only one command per line

       [-a] [path]    = path to tor's control_auth_cookie
                        default: /var/lib/tor/data/control_auth_cookie
                        notice: do not forget to adjust your torrc

       [-s] [time]    = sleep [var] seconds after each command sent
                        default: 1 second
                        notice: for GETCONF, you can use smaller pause times
                        than for SETCONF; this is due to telnet's behaviour.

       [-p] [pwd]     = Use password [var] instead of tor's control_auth_cookie
                        default: not used
                        notice: do not forget to adjust your torrc
                                
       [-P] [port]     = Tor ControlPort
                        default: 9051

       [-v]           = verbose
                        default: not set
                        notice: the default output is the return code ;)
                        You propably want to set -v when running manually

       Examples:      $0 -c "SETCONF bandwidthrate=1mb"
                      $0 -v -c "GETINFO version"
                      $0 -v -s 0 -P 9051 -p foobar -c "GETCONF bandwidthrate"

EOF
exit 2
}

checkprogs()
{
        programs="telnet"
        if [ "$PASSWORD" = "" ]   
        then
                # you only need xxd when using control_auth_cookie
                programs="$programs xxd"
        fi

        for p in $programs
        do
                which $p &>/dev/null            # are you there?
                if [ "$?" != "0" ]
                then
                        echo "$p is missing."
                        exit 2
                fi
        done
}

sendcmd()
{
        echo "$@"
        sleep ${SLEEP_AFTER_CMD}
}

login()
{
        if [ "$PASSWORD" = "" ]
        then
                sendcmd "AUTHENTICATE $(xxd -c 32 -g 0 ${TOR_COOKIE} | awk '{print $2}')"
        else
                sendcmd "AUTHENTICATE \"${PASSWORD}\""
        fi
}

cmdpipe()
{
        login
        sendcmd "$@"
        sendcmd "QUIT"
}

vecho()
{
        if [ $VERBOSE -ge 1 ]
        then
                echo "$@"
        fi
}

myecho()
{
        STR=$(cat)
        vecho "$STR"

        echo "$STR" | if [ "$(grep -c ^"250 ")" = 3 ]
        then
                exit 0
        else
                exit 1
        fi
}

filepipe()
{
        login
        cat "$1" | while read line
        do
                sendcmd "$line"
        done
        sendcmd "QUIT"
}

while getopts ":a:c:s:p:P:f:vh" Option
do
        case $Option in
                a) TOR_COOKIE="${OPTARG}";;
                c) CMD="${OPTARG}";;
                s) SLEEP_AFTER_CMD="${OPTARG}";;
                p) PASSWORD="${OPTARG}";;
                P) TORCTLPORT="${OPTARG}";;
                f) FILE="${OPTARG}";;
                v) VERBOSE=1;;
                h) usage;;
                *) usage;;
        esac
done

if [ -e "$FILE" ]
then
        checkprogs
        filepipe "$FILE" | telnet $TORCTLIP $TORCTLPORT 2>/dev/null | myecho
        exit 4
fi

if [ "$CMD" != "" ]
then
        checkprogs
        cmdpipe $CMD | telnet $TORCTLIP $TORCTLPORT 2>/dev/null | myecho
else
        usage
fi
