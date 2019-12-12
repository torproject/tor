# coding=utf8
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
# Modified by Marcin Cieślak in 2018:
#  - Accept UTF-8
#  - only guess github URLs
#  - stop using ANSI colors
#
# Modified by teor in 2018:
#  - fix github provider detection ('gitHub' or 'gitHubEnterprise', apparently)
#  - make short commits 10 hexdigits long (that's what git does for tor)
#  - generate correct branches and URLs for pull requests and tags
#  - switch to one URL per line

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
export APPVEYOR_ACCOUNT_NAME=isislovecruft
export APPVEYOR_BUILD_VERSION=1
export APPVEYOR_PROJECT_NAME=tor
export APPVEYOR_PULL_REQUEST_NUMBER=pull_request_number
export APPVEYOR_PULL_REQUEST_TITLE=pull_request_title
export APPVEYOR_REPO_BRANCH=repo_branch
export APPVEYOR_REPO_COMMIT=22c95b72e29248dc4de9b85e590ee18f6f587de8
export APPVEYOR_REPO_COMMIT_AUTHOR=isislovecruft
export APPVEYOR_REPO_COMMIT_MESSAGE="some IRC test"
export APPVEYOR_REPO_COMMIT_TIMESTAMP=2018-04-23
export APPVEYOR_REPO_NAME=isislovecruft/tor
export APPVEYOR_REPO_PROVIDER=github
export APPVEYOR_URL=https://ci.appveyor.com
python ./appveyor-irc-notify.py irc.oftc.net:6697 tor-ci '{repo_name} {repo_branch} {short_commit} - {repo_commit_author}: {repo_commit_message}','Build #{build_version} passed. Details: {build_url} |  Commit: {commit_url}

See also https://github.com/gridsync/gridsync/blob/master/appveyor.yml for examples
in Appveyor's YAML:

    on_success:
      - "python scripts/test/appveyor-irc-notify.py irc.oftc.net:6697 tor-ci success
    on_failure:
      - "python scripts/test/appveyor-irc-notify.py irc.oftc.net:6697 tor-ci failure
"""

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import random
import socket
import ssl
import sys
import time


def appveyor_vars():
    """
    Return a dict of key value crafted from appveyor environment variables.
    """

    vars = dict([
            (
                v.replace('APPVEYOR_', '').lower(),
                os.getenv(v, '').decode('utf-8')
            ) for v in [
                'APPVEYOR_ACCOUNT_NAME',
                'APPVEYOR_BUILD_VERSION',
                'APPVEYOR_PROJECT_NAME',
                'APPVEYOR_PULL_REQUEST_HEAD_COMMIT',
                'APPVEYOR_PULL_REQUEST_HEAD_REPO_BRANCH',
                'APPVEYOR_PULL_REQUEST_HEAD_REPO_NAME',
                'APPVEYOR_PULL_REQUEST_NUMBER',
                'APPVEYOR_PULL_REQUEST_TITLE',
                'APPVEYOR_REPO_BRANCH',
                'APPVEYOR_REPO_COMMIT',
                'APPVEYOR_REPO_COMMIT_AUTHOR',
                'APPVEYOR_REPO_COMMIT_AUTHOR_EMAIL',
                'APPVEYOR_REPO_COMMIT_MESSAGE',
                'APPVEYOR_REPO_COMMIT_MESSAGE_EXTENDED',
                'APPVEYOR_REPO_COMMIT_TIMESTAMP',
                'APPVEYOR_REPO_NAME',
                'APPVEYOR_REPO_PROVIDER',
                'APPVEYOR_REPO_TAG_NAME',
                'APPVEYOR_URL',
            ]
    ])

    BUILD_FMT = u'{url}/project/{account_name}/{project_name}/build/{build_version}'

    if vars["repo_tag_name"]:
        BRANCH_FMT = u'{repo_name} {repo_tag_name} {short_commit}'
    else:
        BRANCH_FMT = u'{repo_name} {repo_branch} {short_commit}'

    vars.update(head_commit=vars["repo_commit"])

    if vars["repo_provider"].lower().startswith('github'):
        COMMIT_FMT = u'https://github.com/{repo_name}/commit/{repo_commit}'
        if vars["pull_request_number"]:
            vars.update(head_commit=vars["pull_request_head_commit"])
            BRANCH_FMT = u'{repo_name} {repo_branch} pull {pull_request_head_repo_name} {pull_request_head_repo_branch} {short_commit}'
            COMMIT_FMT = u'https://github.com/{pull_request_head_repo_name}/commit/{pull_request_head_commit}'
            PULL_FMT = u'https://github.com/{repo_name}/pull/{pull_request_number}'
            vars.update(pull_url=PULL_FMT.format(**vars))
        vars.update(commit_url=COMMIT_FMT.format(**vars))

    vars.update(short_commit=vars["head_commit"][:10])

    vars.update(
        build_url=BUILD_FMT.format(**vars),
        branch_detail=BRANCH_FMT.format(**vars),
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
        messages.append(u"{branch_detail} - {repo_commit_author}: {repo_commit_message}")

        if success:
            messages.append(u"Build #{build_version} passed. Details: {build_url}")
        if failure:
            messages.append(u"Build #{build_version} failed. Details: {build_url}")

        if "commit_url" in apvy_vars:
            messages.append(u"Commit: {commit_url}")

        if "pull_url" in apvy_vars:
            messages.append(u"Pull: {pull_url}")

    else:
        messages = sys.argv[3:]
        messages = ' '.join(messages)
        messages = messages.decode("utf-8").split(',')

    print(repr(apvy_vars))
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
            irc_file.send('PONG {}\r\n'.format(response[1]).encode())

        elif response[1] == '433':
            irc_sock.send('NICK {}\r\n'.format(irc_nick).encode())

        elif response[1] == '001':
            time.sleep(5)
            # send notification
            for msg in messages:
                print(u'PRIVMSG #{} :{}'.format(channel, msg).encode("utf-8"))
                irc_sock.send(u'PRIVMSG #{} :{}\r\n'.format(channel, msg).encode("utf-8"))
            time.sleep(5)
            return


if __name__ == '__main__':
    try:
        notify()
    except:
        import traceback
        print('ERROR: Failed to send notification: \n' + traceback.format_exc())
