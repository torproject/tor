#!/usr/bin/python
# Copyright 2014-2015, The Tor Project, Inc
# See LICENSE for licensing information

"""
   Reference implementations for the ed25519 tweaks that Tor uses.

   Includes self-tester and test vector generator.
"""

import slow_ed25519
from slow_ed25519 import *

import os
import random
import slownacl_curve25519
import unittest
import binascii
import textwrap

#define a synonym that doesn't look like 1
ell = l

# This replaces expmod above and makes it go a lot faster.
slow_ed25519.expmod = pow

def curve25519ToEd25519(c, sign):
    u = decodeint(c)
    y = ((u - 1) * inv(u + 1)) % q
    x = xrecover(y)
    if x & 1 != sign: x = q-x
    return encodepoint([x,y])

def blindESK(esk, param):
    h = H("Derive temporary signing key" + param)
    mult = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
    s = decodeint(esk[:32])
    s_prime = (s * mult) % ell
    k = esk[32:]
    assert(len(k) == 32)
    k_prime = H("Derive temporary signing key hash input" + k)[:32]
    return encodeint(s_prime) + k_prime

def blindPK(pk, param):
    h = H("Derive temporary signing key" + param)
    mult = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
    P = decodepoint(pk)
    return encodepoint(scalarmult(P, mult))

def expandSK(sk):
    h = H(sk)
    a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
    k = ''.join([h[i] for i in range(b/8,b/4)])
    assert len(k) == 32
    return encodeint(a)+k

def publickeyFromESK(h):
    a = decodeint(h[:32])
    A = scalarmult(B,a)
    return encodepoint(A)

def signatureWithESK(m,h,pk):
    a = decodeint(h[:32])
    r = Hint(''.join([h[i] for i in range(b/8,b/4)]) + m)
    R = scalarmult(B,r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)

def newSK():
    return os.urandom(32)

# ------------------------------------------------------------

MSG = "This is extremely silly. But it is also incredibly serious business!"

class SelfTest(unittest.TestCase):

    def _testSignatures(self, esk, pk):
        sig = signatureWithESK(MSG, esk, pk)
        checkvalid(sig, MSG, pk)
        bad = False
        try:
            checkvalid(sig, MSG*2, pk)
            bad = True
        except Exception:
            pass

        self.failIf(bad)

    def testExpand(self):
        sk = newSK()
        pk = publickey(sk)
        esk = expandSK(sk)
        sig1 = signature(MSG, sk, pk)
        sig2 = signatureWithESK(MSG, esk, pk)
        self.assertEquals(sig1, sig2)

    def testSignatures(self):
        sk = newSK()
        esk = expandSK(sk)
        pk = publickeyFromESK(esk)
        pk2 = publickey(sk)
        self.assertEquals(pk, pk2)

        self._testSignatures(esk, pk)

    def testDerivation(self):
        priv = slownacl_curve25519.Private()
        pub = priv.get_public()

        ed_pub0 = publickeyFromESK(priv.private)
        sign = (ord(ed_pub0[31]) & 255) >> 7
        ed_pub1 = curve25519ToEd25519(pub.public, sign)

        self.assertEquals(ed_pub0, ed_pub1)

    def testBlinding(self):
        sk = newSK()
        esk = expandSK(sk)
        pk = publickeyFromESK(esk)
        param = os.urandom(32)
        besk = blindESK(esk, param)
        bpk = blindPK(pk, param)
        bpk2 = publickeyFromESK(besk)
        self.assertEquals(bpk, bpk2)

        self._testSignatures(besk, bpk)

# ------------------------------------------------------------

# From pprint.pprint([ binascii.b2a_hex(os.urandom(32)) for _ in xrange(8) ])
RAND_INPUTS = [
  '26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36',
  'fba7a5366b5cb98c2667a18783f5cf8f4f8d1a2ce939ad22a6e685edde85128d',
  '67e3aa7a14fac8445d15e45e38a523481a69ae35513c9e4143eb1c2196729a0e',
  'd51385942033a76dc17f089a59e6a5a7fe80d9c526ae8ddd8c3a506b99d3d0a6',
  '5c8eac469bb3f1b85bc7cd893f52dc42a9ab66f1b02b5ce6a68e9b175d3bb433',
  'eda433d483059b6d1ff8b7cfbd0fe406bfb23722c8f3c8252629284573b61b86',
  '4377c40431c30883c5fbd9bc92ae48d1ed8a47b81d13806beac5351739b5533d',
  'c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b']

# From pprint.pprint([ binascii.b2a_hex(os.urandom(32)) for _ in xrange(8) ])
BLINDING_PARAMS = [
  '54a513898b471d1d448a2f3c55c1de2c0ef718c447b04497eeb999ed32027823',
  '831e9b5325b5d31b7ae6197e9c7a7baf2ec361e08248bce055908971047a2347',
  'ac78a1d46faf3bfbbdc5af5f053dc6dc9023ed78236bec1760dadfd0b2603760',
  'f9c84dc0ac31571507993df94da1b3d28684a12ad14e67d0a068aba5c53019fc',
  'b1fe79d1dec9bc108df69f6612c72812755751f21ecc5af99663b30be8b9081f',
  '81f1512b63ab5fb5c1711a4ec83d379c420574aedffa8c3368e1c3989a3a0084',
  '97f45142597c473a4b0e9a12d64561133ad9e1155fe5a9807fe6af8a93557818',
  '3f44f6a5a92cde816635dfc12ade70539871078d2ff097278be2a555c9859cd0']

PREFIX = "ED25519_"

def writeArray(name, array):
    print "static const char *{prefix}{name}[] = {{".format(
        prefix=PREFIX,name=name)
    for a in array:
        h = binascii.b2a_hex(a)
        if len(h) > 70:
            h1 = h[:70]
            h2 = h[70:]
            print '  "{0}"\n      "{1}",'.format(h1,h2)
        else:
            print '  "{0}",'.format(h)
    print "};\n"

def comment(text, initial="/**"):
    print initial
    print textwrap.fill(text,initial_indent=" * ",subsequent_indent=" * ")
    print " */"

def makeTestVectors():
    comment("""Test vectors for our ed25519 implementation and related
               functions. These were automatically generated by the
               ed25519_exts_ref.py script.""", initial="/*")


    comment("""Secret key seeds used as inputs for the ed25519 test vectors.
               Randomly generated. """)
    secretKeys = [ binascii.a2b_hex(r) for r in RAND_INPUTS ]
    writeArray("SECRET_KEYS", secretKeys)

    comment("""Secret ed25519 keys after expansion from seeds. This is how Tor
               represents them internally.""")
    expandedSecretKeys = [ expandSK(sk) for sk in secretKeys ]
    writeArray("EXPANDED_SECRET_KEYS", expandedSecretKeys)

    comment("""Public keys derived from the above secret keys""")
    publicKeys = [ publickey(sk) for sk in secretKeys ]
    writeArray("PUBLIC_KEYS", publicKeys)

    comment("""The curve25519 public keys from which the ed25519 keys can be
               derived.  Used to test our 'derive ed25519 from curve25519'
               code.""")
    writeArray("CURVE25519_PUBLIC_KEYS",
               (slownacl_curve25519.smult_curve25519_base(sk[:32])
                   for sk in expandedSecretKeys))

    comment("""Parameters used for key blinding tests. Randomly generated.""")
    blindingParams =  [ binascii.a2b_hex(r) for r in BLINDING_PARAMS ]
    writeArray("BLINDING_PARAMS", blindingParams)

    comment("""Blinded secret keys for testing key blinding.  The nth blinded
               key corresponds to the nth secret key blidned with the nth
               blinding parameter.""")
    writeArray("BLINDED_SECRET_KEYS",
               (blindESK(expandSK(sk), bp)
                for sk,bp in zip(secretKeys,blindingParams)))

    comment("""Blinded public keys for testing key blinding.  The nth blinded
               key corresponds to the nth public key blidned with the nth
               blinding parameter.""")
    writeArray("BLINDED_PUBLIC_KEYS",
               (blindPK(pk, bp) for pk,bp in zip(publicKeys,blindingParams)))

    comment("""Signatures of the public keys, made with their corresponding
               secret keys.""")
    writeArray("SELF_SIGNATURES",
               (signature(pk, sk, pk) for pk,sk in zip(publicKeys,secretKeys)))



if __name__ == '__main__':
    import sys
    if len(sys.argv) == 1 or sys.argv[1] not in ("SelfTest", "MakeVectors"):
        print "You should specify one of 'SelfTest' or 'MakeVectors'"
        sys.exit(1)
    if sys.argv[1] == 'SelfTest':
        unittest.main()
    else:
        makeTestVectors()


