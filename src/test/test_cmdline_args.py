#!/usr/bin/python

import binascii
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

TOR = "./src/or/tor"
TOP_SRCDIR = "."

if len(sys.argv) > 1:
    TOR = sys.argv[1]
    del sys.argv[1]

if len(sys.argv) > 1:
    TOP_SRCDIR = sys.argv[1]
    del sys.argv[1]

class UnexpectedSuccess(Exception):
    pass

class UnexpectedFailure(Exception):
    pass

def contents(fn):
    f = open(fn)
    try:
        return f.read()
    finally:
        f.close()

def run_tor(args, failure=False):
    p = subprocess.Popen([TOR] + args, stdout=subprocess.PIPE)
    output, _ = p.communicate()
    result = p.poll()
    if result and not failure:
        raise UnexpectedFailure()
    elif not result and failure:
        raise UnexpectedSuccess()
    return output

def spaceify_fp(fp):
    for i in xrange(0, len(fp), 4):
        yield fp[i:i+4]

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
        main_c = os.path.join(TOP_SRCDIR, "src", "or", "main.c")

        if os.stat(TOR).st_mtime < os.stat(main_c).st_mtime:
            self.skipTest(TOR+" not up to date")
        out = run_tor(["--digests"])
        main_line = [ l for l in lines(out) if l.endswith("/main.c") ]
        digest, name = main_line[0].split()
        actual = hashlib.sha1(open(main_c).read()).hexdigest()
        self.assertEquals(digest, actual)

    def test_dump_options(self):
        default_torrc = tempfile.NamedTemporaryFile(delete=False)
        torrc = tempfile.NamedTemporaryFile(delete=False)
        torrc.write("SocksPort 9999")
        torrc.close()
        default_torrc.write("SafeLogging 0")
        default_torrc.close()
        out_sh = out_nb = out_fl = None
        opts = [ "-f", torrc.name,
                 "--defaults-torrc", default_torrc.name ]
        try:
            out_sh = run_tor(["--dump-config", "short"]+opts)
            out_nb = run_tor(["--dump-config", "non-builtin"]+opts)
            out_fl = run_tor(["--dump-config", "full"]+opts)
            out_nr = run_tor(["--dump-config", "bliznert"]+opts,
                             failure=True)

            out_verif = run_tor(["--verify-config"]+opts)
        finally:
            os.unlink(torrc.name)
            os.unlink(default_torrc.name)

        self.assertEquals(len(lines(out_sh)), 2)
        self.assert_(lines(out_sh)[0].startswith("DataDirectory "))
        self.assertEquals(lines(out_sh)[1:],
            [ "SocksPort 9999" ])

        self.assertEquals(len(lines(out_nb)), 2)
        self.assertEquals(lines(out_nb),
            [ "SafeLogging 0",
              "SocksPort 9999" ])

        out_fl = lines(out_fl)
        self.assert_(len(out_fl) > 100)
        self.assertIn("SocksPort 9999", out_fl)
        self.assertIn("SafeLogging 0", out_fl)
        self.assertIn("ClientOnly 0", out_fl)

        self.assert_(out_verif.endswith("Configuration was valid\n"))

    def test_list_fingerprint(self):
        tmpdir = tempfile.mkdtemp(prefix='ttca_')
        torrc = tempfile.NamedTemporaryFile(delete=False)
        torrc.write("ORPort 9999\n")
        torrc.write("DataDirectory %s\n"%tmpdir)
        torrc.write("Nickname tippi")
        torrc.close()
        opts = ["-f", torrc.name]
        try:
            out = run_tor(["--list-fingerprint"]+opts)
            fp = contents(os.path.join(tmpdir, "fingerprint"))
        finally:
            os.unlink(torrc.name)
            shutil.rmtree(tmpdir)

        out = lines(out)
        lastlog = strip_log_junk(out[-2])
        lastline = out[-1]
        fp = fp.strip()
        nn_fp = fp.split()[0]
        space_fp = " ".join(spaceify_fp(fp.split()[1]))
        self.assertEquals(lastlog,
              "Your Tor server's identity key fingerprint is '%s'"%fp)
        self.assertEquals(lastline, "tippi %s"%space_fp)
        self.assertEquals(nn_fp, "tippi")

    def test_list_options(self):
        out = lines(run_tor(["--list-torrc-options"]))
        self.assert_(len(out)>100)
        self.assert_(out[0] <= 'AccountingMax')
        self.assert_("UseBridges" in out)
        self.assert_("SocksPort" in out)

    def test_cmdline_args(self):
        default_torrc = tempfile.NamedTemporaryFile(delete=False)
        torrc = tempfile.NamedTemporaryFile(delete=False)
        torrc.write("SocksPort 9999\n")
        torrc.write("SocksPort 9998\n")
        torrc.write("ORPort 9000\n")
        torrc.write("ORPort 9001\n")
        torrc.write("Nickname eleventeen\n")
        torrc.write("ControlPort 9500\n")
        torrc.close()
        default_torrc.write("")
        default_torrc.close()
        out_sh = out_nb = out_fl = None
        opts = [ "-f", torrc.name,
                 "--defaults-torrc", default_torrc.name,
                 "--dump-config", "short" ]
        try:
            out_1 = run_tor(opts)
            out_2 = run_tor(opts+["+ORPort", "9003",
                                  "SocksPort", "9090",
                                  "/ControlPort",
                                  "/TransPort",
                                  "+ExtORPort", "9005"])
        finally:
            os.unlink(torrc.name)
            os.unlink(default_torrc.name)

        out_1 = [ l for l in lines(out_1) if not l.startswith("DataDir") ]
        out_2 = [ l for l in lines(out_2) if not l.startswith("DataDir") ]

        self.assertEquals(out_1,
                          ["ControlPort 9500",
                           "Nickname eleventeen",
                           "ORPort 9000",
                           "ORPort 9001",
                           "SocksPort 9999",
                           "SocksPort 9998"])
        self.assertEquals(out_2,
                          ["ExtORPort 9005",
                           "Nickname eleventeen",
                           "ORPort 9000",
                           "ORPort 9001",
                           "ORPort 9003",
                           "SocksPort 9090"])

if __name__ == '__main__':
    unittest.main()
