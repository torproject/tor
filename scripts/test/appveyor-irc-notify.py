# Copyright (C) 2015-2016 Christopher R. Wood
# Copyright (c) 2018 The Tor Project
# Copyright (c) 2018 isis agora lovecruft
# 
# From: https://raw.githubusercontent.com/gridsync/gridsync/def54f8166089b733d166665fdabcad4cdc526d8/misc/irc-notify.py
# and: https://github.com/gridsync/gridsync
# 
# Modified by nexB on October 2016:
#  - rework the handling of environment variables.
#  - made the script use functions
#  - support only Appveyor loading its environment variable to craft IRC notices.
#
# Modified by isis agora lovecruft <isis@torproject.org> in 2018:
#  - Make IRC server configurable.
#  - Make bot IRC nick deterministic.
#  - Make bot join the channel rather than sending NOTICE messages externally.
#  - Fix a bug which always caused sys.exit() to be logged as a traceback.
#  - Actually reset the IRC colour codes after printing.
#
# This program is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with this
# program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street,
# Fifth Floor, Boston, MA 02110-1301 USA.

"""Simple AppVeyor IRC notification script.

The first argument is an IRC server and port; the second is the channel. Other
arguments passed to the script will be sent as notice messages content and any
{var}-formatted environment variables will be expanded automatically, replaced
with a corresponding Appveyor environment variable value. Use commas to
delineate multiple messages.


Example:
export APPVEYOR_URL=https://ci.appveyor.com
export APPVEYOR_PROJECT_NAME=tor
export APPVEYOR_REPO_COMMIT_AUTHOR=isislovecruft
export APPVEYOR_REPO_COMMIT_TIMESTAMP=2018-04-23
export APPVEYOR_REPO_PROVIDER=gihub
export APPVEYOR_REPO_BRANCH=repo_branch
export APPVEYOR_PULL_REQUEST_TITLE=pull_request_title
export APPVEYOR_BUILD_VERSION=1
export APPVEYOR_REPO_COMMIT=22c95b72e29248dc4de9b85e590ee18f6f587de8
export APPVEYOR_REPO_COMMIT_MESSAGE="some IRC test"
export APPVEYOR_ACCOUNT_NAME=isislovecruft
export APPVEYOR_PULL_REQUEST_NUMBER=pull_request_number
export APPVEYOR_REPO_NAME=isislovecruft/tor
python ./appveyor-irc-notify.py irc.oftc.net:6697 tor-ci '{repo_name} {color_white}{branch}{color_reset} {short_commit} - {author}: {message}','Build #{build_version} {color_green}passed{color_reset}. Details: {color_blue}{build_url}{color_reset} |  Commit: {color_blue}{commit_url}{color_reset}'

See also https://github.com/gridsync/gridsync/blob/master/appveyor.yml for examples
in Appveyor's YAML:

    on_success:
      - "python scripts/test/appveyor-irc-notify.py irc.oftc.net:6697 tor-ci success
    on_failure:
      - "python scripts/test/appveyor-irc-notify.py irc.oftc.net:6697 tor-ci failure
"""

from __future__ import print_function
from __future__ import absolute_import

import os
from os import environ
import random
import socket
import ssl
import sys
import time


def appveyor_vars():
    """
    Return a dict of key value carfted from appveyor environment variables.
    """

    appveyor_url = environ.get('APPVEYOR_URL')
    message_extended = environ.get('APPVEYOR_REPO_COMMIT_MESSAGE_EXTENDED')
    branch = environ.get('APPVEYOR_REPO_BRANCH')
    author = environ.get('APPVEYOR_REPO_COMMIT_AUTHOR')
    author_email = environ.get('APPVEYOR_REPO_COMMIT_AUTHOR_EMAIL')
    timestamp = environ.get('APPVEYOR_REPO_COMMIT_TIMESTAMP')
    repo_provider = environ.get('APPVEYOR_REPO_PROVIDER')
    project_name = environ.get('APPVEYOR_PROJECT_NAME')
    pull_request_title = environ.get('APPVEYOR_PULL_REQUEST_TITLE')
    build_version = environ.get('APPVEYOR_BUILD_VERSION')
    commit = environ.get('APPVEYOR_REPO_COMMIT')
    message = environ.get('APPVEYOR_REPO_COMMIT_MESSAGE')
    account_name = environ.get('APPVEYOR_ACCOUNT_NAME')
    pull_request_number = environ.get('APPVEYOR_PULL_REQUEST_NUMBER')
    repo_name = environ.get('APPVEYOR_REPO_NAME')

    short_commit = commit[:7]
    build_url = '{appveyor_url}/project/{account_name}/{project_name}/build/{build_version}'.format(**locals())
    commit_url = 'https://{repo_provider}.com/{repo_name}/commit/{short_commit}'.format(**locals())

    vars = dict(
        appveyor_url=appveyor_url,
        account_name=account_name,
        project_name=project_name,
        build_version=build_version,

        build_url=build_url,

        repo_provider=repo_provider,
        repo_name=repo_name,
        branch=branch,
        author=author,
        author_email=author_email,
        timestamp=timestamp,
        commit=commit,
        short_commit=short_commit,
        message=message,
        message_extended=message_extended,

        pull_request_title=pull_request_title,
        pull_request_number=pull_request_number,

        commit_url=commit_url,

        color_white='\x030',
        color_blue='\x032',
        color_green='\x033',
        color_red='\x034',
        color_reset='\x0F',
    )
    return vars


def notify():
    """
    Send IRC notification
    """
    apvy_vars = appveyor_vars()

    server, port = sys.argv[1].rsplit(":", 1)
    channel = sys.argv[2]
    success = sys.argv[3] == "success"
    failure = sys.argv[3] == "failure"

    if success or failure:
        messages = []
        messages.append("{repo_name} {color_white}{branch}{color_reset} {short_commit} - {author}: {message}")

        if success:
            messages.append("Build #{build_version} {color_green}passed{color_reset}. Details: {color_blue}{build_url}{color_reset} Commit: {color_blue}{commit_url}{color_reset}")
        if failure:
            messages.append("Build #{build_version} {color_red}failed{color_reset}. Details: {color_blue}{build_url}{color_reset} Commit: {color_blue}{commit_url}{color_reset}")
    else:
        messages = sys.argv[3:]
        messages = ' '.join(messages)
        messages = messages.split(',')

    messages = [msg.format(**apvy_vars).strip() for msg in messages]

    irc_username = 'appveyor-ci'
    irc_nick = irc_username

    # establish connection
    irc_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    irc_sock.connect((socket.gethostbyname(server), int(port)))
    irc_sock.send('NICK {0}\r\nUSER {0} * 0 :{0}\r\n'.format(irc_username).encode())
    irc_sock.send('JOIN #{0}\r\n'.format(channel).encode())
    irc_file = irc_sock.makefile()

    while irc_file:
        line = irc_file.readline()
        print(line.rstrip())
        response = line.split()

        if response[0] == 'PING':
            irc_file.send('PONG {}\r\n'.format(reponse[1]).encode())

        elif response[1] == '433':
            irc_sock.send('NICK {}\r\n'.format(irc_nick).encode())

        elif response[1] == '001':
            time.sleep(5)
            # send notification
            for msg in messages:
                print('PRIVMSG #{} :{}'.format(channel, msg))
                irc_sock.send('PRIVMSG #{} :{}\r\n'.format(channel, msg).encode())
            time.sleep(5)
            return


if __name__ == '__main__':
    try:
        notify()
    except:
        import traceback
        print('ERROR: Failed to send notification: \n' + traceback.format_exc())
