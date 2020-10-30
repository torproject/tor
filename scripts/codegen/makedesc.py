#!/usr/bin/env python
# Copyright 2014-2019, The Tor Project, Inc.
# See LICENSE for license information

# This is a kludgey python script that uses ctypes and openssl to sign
# router descriptors and extrainfo documents and put all the keys in
# the right places.  There are examples at the end of the file.

# I've used this to make inputs for unit tests.  I wouldn't suggest
# using it for anything else.

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import base64
import binascii
import ctypes
import ctypes.util
import hashlib
import optparse
import os
import re
import struct
import time

import slow_ed25519
import slownacl_curve25519
import ed25519_exts_ref

try:
    xrange  # Python 2
except NameError:
    xrange = range  # Python 3

# Pull in the openssl stuff we need.

crypt = ctypes.CDLL(ctypes.util.find_library('crypto'))
BIO_s_mem = crypt.BIO_s_mem
BIO_s_mem.argtypes = []
BIO_s_mem.restype = ctypes.c_void_p

BIO_new = crypt.BIO_new
BIO_new.argtypes = [ctypes.c_void_p]
BIO_new.restype = ctypes.c_void_p

crypt.BIO_free.argtypes = [ctypes.c_void_p]
crypt.BIO_free.restype = ctypes.c_int

crypt.BIO_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p ]
crypt.BIO_ctrl.restype = ctypes.c_long

crypt.PEM_write_bio_RSAPublicKey.argtypes = [ ctypes.c_void_p, ctypes.c_void_p ]
crypt.PEM_write_bio_RSAPublicKey.restype = ctypes.c_int

RSA_generate_key = crypt.RSA_generate_key
RSA_generate_key.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
RSA_generate_key.restype = ctypes.c_void_p

RSA_private_encrypt = crypt.RSA_private_encrypt
RSA_private_encrypt.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int ]
RSA_private_encrypt.restype = ctypes.c_int

i2d_RSAPublicKey = crypt.i2d_RSAPublicKey
i2d_RSAPublicKey.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)
]
i2d_RSAPublicKey.restype = ctypes.c_int


HEADER = """\
router fred 127.0.0.1 9001 0 9002
identity-ed25519
{d.ED_CERT}
signing-key
{d.RSA_IDENTITY}
master-key-ed25519 {d.ED_IDENTITY}
onion-key
{d.RSA_ONION_KEY}
ntor-onion-key {d.NTOR_ONION_KEY}
ntor-onion-key-crosscert {d.NTOR_CROSSCERT_SIGN}
{d.NTOR_CROSSCERT}
onion-key-crosscert
{d.RSA_CROSSCERT_ED}
"""

FOOTER="""

"""

def rsa_sign(msg, rsa):
    buf = ctypes.create_string_buffer(2048)
    n = RSA_private_encrypt(len(msg), msg, buf, rsa, 1)
    if n <= 0:
        raise Exception()
    return buf.raw[:n]

def b64(x1):
    x = binascii.b2a_base64(x1)
    res = []
    for i in xrange(0, len(x), 64):
        res.append((x[i:i+64]).decode("ascii"))
    return "\n".join(res)

def bio_extract(bio):
    buf = ctypes.c_char_p()
    length = crypt.BIO_ctrl(bio, 3, 0, ctypes.byref(buf))
    return ctypes.string_at(buf, length)

def make_rsa_key(e=65537):
    rsa = crypt.RSA_generate_key(1024, e, None, None)
    bio = BIO_new(BIO_s_mem())
    crypt.PEM_write_bio_RSAPublicKey(bio, rsa)
    pem = bio_extract(bio).rstrip()
    crypt.BIO_free(bio)
    buf = ctypes.create_string_buffer(1024)
    pBuf = ctypes.c_char_p(ctypes.addressof(buf))
    n = crypt.i2d_RSAPublicKey(rsa, ctypes.byref(pBuf))
    s = buf.raw[:n]
    digest = hashlib.sha1(s).digest()
    pem = pem.decode("ascii")
    return (rsa,pem,digest)

def makeEdSigningKeyCert(sk_master, pk_master, pk_signing, date,
                         includeSigning=False, certType=1):
    assert len(pk_signing) == len(pk_master) == 32
    expiration = struct.pack(b"!L", date//3600)
    if includeSigning:
        extensions = b"\x01\x00\x20\x04\x00%s"%(pk_master)
    else:
        extensions = b"\x00"
    signed = b"\x01%s%s\x01%s%s" % (
        bytes([certType]), expiration, pk_signing, extensions)
    signature = ed25519_exts_ref.signatureWithESK(signed, sk_master, pk_master)
    assert len(signature) == 64
    return signed+signature

def objwrap(identifier, body):
    return ("-----BEGIN {0}-----\n"
            "{1}"
            "-----END {0}-----").format(identifier, body)

MAGIC1 = "<<<<<<MAGIC>>>>>>"
MAGIC2 = "<<<<<!#!#!#XYZZY#!#!#!>>>>>"

class OnDemandKeys(object):
    def __init__(self, certDate=None):
        if certDate is None:
            certDate = int(time.time()) + 86400
        self.certDate = certDate
        self.rsa_id = None
        self.rsa_onion_key = None
        self.ed_id_sk = None
        self.ntor_sk = None
        self.ntor_crosscert = None
        self.rsa_crosscert_ed = None
        self.rsa_crosscert_noed = None

    @property
    def RSA_IDENTITY(self):
        if self.rsa_id is None:
            self.rsa_id, self.rsa_ident_pem, self.rsa_id_digest = make_rsa_key()

        return self.rsa_ident_pem

    @property
    def RSA_ID_DIGEST(self):
        self.RSA_IDENTITY
        return self.rsa_id_digest

    @property
    def RSA_FINGERPRINT_NOSPACE(self):
        return binascii.b2a_hex(self.RSA_ID_DIGEST).upper().decode("ascii")

    @property
    def RSA_ONION_KEY(self):
        if self.rsa_onion_key is None:
            self.rsa_onion_key, self.rsa_onion_pem, _ = make_rsa_key()

        return self.rsa_onion_pem

    @property
    def RSA_FINGERPRINT(self):
        hexdigest = self.RSA_FINGERPRINT_NOSPACE
        return " ".join(hexdigest[i:i+4] for i in range(0,len(hexdigest),4))

    @property
    def RSA_SIGNATURE(self):
        return MAGIC1

    @property
    def ED_SIGNATURE(self):
        return MAGIC2

    @property
    def NTOR_ONION_KEY(self):
        if self.ntor_sk is None:
            self.ntor_sk = slownacl_curve25519.Private()
            self.ntor_pk = self.ntor_sk.get_public()
        return base64.b64encode(self.ntor_pk.serialize()).decode("ascii")

    @property
    def ED_CERT(self):
        if self.ed_id_sk is None:
            self.ed_id_sk = ed25519_exts_ref.expandSK(os.urandom(32))
            self.ed_signing_sk = ed25519_exts_ref.expandSK(os.urandom(32))
            self.ed_id_pk = ed25519_exts_ref.publickeyFromESK(self.ed_id_sk)
            self.ed_signing_pk = ed25519_exts_ref.publickeyFromESK(self.ed_signing_sk)
            self.ed_cert = makeEdSigningKeyCert(self.ed_id_sk, self.ed_id_pk, self.ed_signing_pk, self.certDate, includeSigning=True, certType=4)

        return objwrap('ED25519 CERT', b64(self.ed_cert))

    @property
    def ED_IDENTITY(self):
        self.ED_CERT
        return binascii.b2a_base64(self.ed_id_pk).strip().decode("ascii")

    @property
    def NTOR_CROSSCERT(self):
        if self.ntor_crosscert is None:
            self.ED_CERT
            self.NTOR_ONION_KEY

            ed_privkey = self.ntor_sk.serialize() + os.urandom(32)
            ed_pub0 = ed25519_exts_ref.publickeyFromESK(ed_privkey)
            sign = ((ed_pub0[31]) & 255) >> 7

            self.ntor_crosscert = makeEdSigningKeyCert(self.ntor_sk.serialize() + os.urandom(32), ed_pub0, self.ed_id_pk, self.certDate, certType=10)
            self.ntor_crosscert_sign = sign

        return objwrap('ED25519 CERT', b64(self.ntor_crosscert))

    @property
    def NTOR_CROSSCERT_SIGN(self):
        self.NTOR_CROSSCERT
        return self.ntor_crosscert_sign

    @property
    def RSA_CROSSCERT_NOED(self):
        if self.rsa_crosscert_noed is None:
            self.RSA_ONION_KEY
            signed = self.RSA_ID_DIGEST
            self.rsa_crosscert_noed = rsa_sign(signed, self.rsa_onion_key)
        return objwrap("CROSSCERT",b64(self.rsa_crosscert_noed))

    @property
    def RSA_CROSSCERT_ED(self):
        if self.rsa_crosscert_ed is None:
            self.RSA_ONION_KEY
            self.ED_CERT
            signed = self.RSA_ID_DIGEST + self.ed_id_pk
            self.rsa_crosscert_ed = rsa_sign(signed, self.rsa_onion_key)
        return objwrap("CROSSCERT",b64(self.rsa_crosscert_ed))

    def sign_desc(self, body):
        idx = body.rfind("\nrouter-sig-ed25519 ")
        if idx >= 0:
            self.ED_CERT
            signed_part = body[:idx+len("\nrouter-sig-ed25519 ")]
            signed_part = "Tor router descriptor signature v1" + signed_part
            digest = hashlib.sha256(signed_part.encode("utf-8")).digest()
            ed_sig = ed25519_exts_ref.signatureWithESK(digest,
                                      self.ed_signing_sk, self.ed_signing_pk)

            body = body.replace(MAGIC2, base64.b64encode(ed_sig).decode("ascii").replace("=",""))

        self.RSA_IDENTITY
        idx = body.rindex("\nrouter-signature")
        end_of_sig = body.index("\n", idx+1)

        signed_part = body[:end_of_sig+1]

        digest = hashlib.sha1(signed_part.encode("utf-8")).digest()
        assert len(digest) == 20

        rsasig = rsa_sign(digest, self.rsa_id)

        body = body.replace(MAGIC1, objwrap("SIGNATURE", b64(rsasig)))

        return body


def signdesc(body, args_out=None):
    rsa, ident_pem, id_digest = make_rsa_key()
    _, onion_pem, _ = make_rsa_key()

    need_ed = '{ED25519-CERT}' in body or '{ED25519-SIGNATURE}' in body
    if need_ed:
        sk_master = os.urandom(32)
        sk_signing = os.urandom(32)
        pk_master = slow_ed25519.pubkey(sk_master)
        pk_signing = slow_ed25519.pubkey(sk_signing)

    hexdigest = binascii.b2a_hex(id_digest).upper()
    fingerprint = " ".join(hexdigest[i:i+4] for i in range(0,len(hexdigest),4))

    MAGIC = "<<<<<<MAGIC>>>>>>"
    MORE_MAGIC = "<<<<<!#!#!#XYZZY#!#!#!>>>>>"
    args = {
        "RSA-IDENTITY" : ident_pem,
        "ONION-KEY" : onion_pem,
        "FINGERPRINT" : fingerprint,
        "FINGERPRINT-NOSPACE" : hexdigest,
        "RSA-SIGNATURE" : MAGIC
    }
    if need_ed:
        args['ED25519-CERT'] = makeEdSigningKeyCert(
            sk_master, pk_master, pk_signing)
        args['ED25519-SIGNATURE'] = MORE_MAGIC

    if args_out:
        args_out.update(args)
    body = body.format(**args)

    idx = body.rindex("\nrouter-signature")
    end_of_sig = body.index("\n", idx+1)

    signed_part = body[:end_of_sig+1]

    digest = hashlib.sha1(signed_part).digest()
    assert len(digest) == 20

    buf = ctypes.create_string_buffer(1024)
    n = RSA_private_encrypt(20, digest, buf, rsa, 1)
    sig = buf.raw[:n]

    sig = """-----BEGIN SIGNATURE-----
%s
-----END SIGNATURE-----""" % b64(sig).rstrip()
    body = body.replace(MAGIC, sig)

    return body.rstrip()

def print_c_string(ident, body):
    print("static const char %s[] =" % ident)
    for line in body.split("\n"):
        print('  "%s\\n"' %(line))
    print("  ;")

def emit_ri(name, body):
    info = OnDemandKeys()
    body = body.format(d=info)
    body = info.sign_desc(body)
    print_c_string("EX_RI_%s"%name.upper(), body)

def emit_ei(name, body, fields):
    info = OnDemandKeys()
    body = body.format(d=info)
    body = info.sign_desc(body)
    print_c_string("EX_EI_%s"%name.upper(), body)

    print('ATTR_UNUSED static const char EX_EI_{NAME}_FP[] = "{d.RSA_FINGERPRINT_NOSPACE}";'.format(
        d=info, NAME=name.upper()))
    print("ATTR_UNUSED")
    print_c_string("EX_EI_%s_KEY"%name.upper(), info.RSA_IDENTITY)

def analyze(s):
    while s:
        fields = {}
        s_pre = s
        while s.startswith(":::"):
            first,s=s.split("\n", 1)
            m = re.match(r'^:::(\w+)=(.*)',first)
            if not m:
                raise ValueError(first)
            k,v = m.groups()
            fields[k] = v
        if "name" not in fields:
            print(repr(s_pre))

        idx = s.find(":::")
        if idx != -1:
            body = s[:idx].rstrip()
            s = s[idx:]
        else:
            body = s.rstrip()
            s = ""

        yield (fields, body)

def emit_entry(fields, s):
    try:
        name = fields['name']
        tp = fields['type']
    except KeyError:
        raise ValueError("missing required field")

    if tp == 'ei':
        emit_ei(name, s, fields)
    elif tp == 'ri':
        emit_ri(name, s)
    else:
        raise ValueError("unrecognized type")

def process_file(s):
    print("""\
/* These entries are automatically generated by makedesc.py to make sure
 * that their keys and signatures are right except when otherwise
 * specified. */
""")
    for (fields, s) in analyze(s):
        emit_entry(fields, s)

if __name__ == '__main__':
    import sys
    for fn in sys.argv[1:]:
        process_file(open(fn).read())
