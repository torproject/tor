#!/usr/bin/python

import binascii
import hashlib
import os
import re
import subprocess
import tempfile
import unittest

TOR = "./src/or/tor-cov"
TOPDIR = "."

class UnexpectedSuccess(Exception):
    pass

class UnexpectedFailure(Exception):
    pass

def run_tor(args, failure=False):
    p = subprocess.Popen([TOR] + args, stdout=subprocess.PIPE)
    output, _ = p.communicate()
    result = p.poll()
    if result and not failure:
        raise UnexpectedFailure()
    elif not result and failure:
        raise UnexpectedSuccess()
    return output

def lines(s):
    out = s.split("\n")
    if out and out[-1] == '':
        del out[-1]
    return out

def strip_log_junk(line):
    m = re.match(r'([^\[]+\[[a-z]*\] *)(.*)', line)
    if not m:
        return ""+line
    return m.group(2).strip()

class CmdlineTests(unittest.TestCase):

    def test_version(self):
        out = run_tor(["--version"])
        self.failUnless(out.startswith("Tor version "))
        self.assertEquals(len(lines(out)), 1)

    def test_quiet(self):
        out = run_tor(["--quiet", "--quumblebluffin", "1"], failure=True)
        self.assertEquals(out, "")

    def test_help(self):
        out = run_tor(["--help"], failure=False)
        out2 = run_tor(["-h"], failure=False)
        self.assert_(out.startswith("Copyright (c) 2001"))
        self.assert_(out.endswith(
            "tor -f <torrc> [args]\n"
            "See man page for options, or https://www.torproject.org/ for documentation.\n"))
        self.assert_(out == out2)

    def test_hush(self):
        torrc = tempfile.NamedTemporaryFile(delete=False)
        torrc.close()
        try:
            out = run_tor(["--hush", "-f", torrc.name,
                           "--quumblebluffin", "1"], failure=True)
        finally:
            os.unlink(torrc.name)
        self.assertEquals(len(lines(out)), 2)
        ln = [ strip_log_junk(l) for l in lines(out) ]
        self.assertEquals(ln[0], "Failed to parse/validate config: Unknown option 'quumblebluffin'.  Failing.")
        self.assertEquals(ln[1], "Reading config failed--see warnings above.")

    def test_missing_argument(self):
        out = run_tor(["--hush", "--hash-password"], failure=True)
        self.assertEquals(len(lines(out)), 2)
        ln = [ strip_log_junk(l) for l in lines(out) ]
        self.assertEquals(ln[0], "Command-line option '--hash-password' with no value. Failing.")

    def test_hash_password(self):
        out = run_tor(["--hash-password", "woodwose"])
        result = lines(out)[-1]
        self.assertEquals(result[:3], "16:")
        self.assertEquals(len(result), 61)
        r = binascii.a2b_hex(result[3:])
        self.assertEquals(len(r), 29)

        salt, how, hashed = r[:8], r[8], r[9:]
        self.assertEquals(len(hashed), 20)

        count = (16 + (ord(how) & 15)) << ((ord(how) >> 4) + 6)
        stuff = salt + "woodwose"
        repetitions = count // len(stuff) + 1
        inp = stuff * repetitions
        inp = inp[:count]

        self.assertEquals(hashlib.sha1(inp).digest(), hashed)

    def test_digests(self):
        main_c = os.path.join(TOPDIR, "src", "or", "main.c")

        if os.stat(TOR).st_mtime < os.stat(main_c).st_mtime:
            self.skipTest(TOR+" not up to date")
        out = run_tor(["--digests"])
        main_line = [ l for l in lines(out) if l.endswith("/main.c") ]
        digest, name = main_line[0].split()
        actual = hashlib.sha1(open(main_c).read()).hexdigest()
        self.assertEquals(digest, actual)


if __name__ == '__main__':

    unittest.main()
