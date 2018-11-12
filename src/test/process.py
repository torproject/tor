#!/usr/bin/env python3

import sys
import os

def cmd_env(command, arguments):
    print("%s" % os.environ.get(arguments[0], "N/A"))

def cmd_ping(command, arguments):
    a = " ".join(arguments)
    print("pong %s" % a)

def cmd_add(command, arguments):
    a = int(arguments[0])
    b = int(arguments[1])
    print("%d" % (a + b))

def cmd_exit(command, arguments):
    sys.exit(0)

def cmd_unknown(command, arguments):
    print("Unknown command: %s" % command)

def handle_command(command, arguments):
    commands = {
        "add":     cmd_add,
        "env":     cmd_env,
        "exit":    cmd_exit,
        "ping":    cmd_ping,
        "unknown": cmd_unknown,
    }

    handler = commands.get(command, cmd_unknown)
    handler(command, arguments)

def handle_line(line):
    if line == "":
        return

    if ":" in line:
        tokens = line.split(":")
        command = tokens[0]
        arguments = tokens[1].split(" ")
    else:
        command = line
        arguments = []

    handle_command(command, arguments)

if __name__ == '__main__':
    while True:
        line = sys.stdin.readline()
        handle_line(line.strip())
