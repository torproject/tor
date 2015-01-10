#!/usr/bin/python
# Copyright 2014-2015, The Tor Project, Inc.
# See LICENSE for license information

# This is a kludgey python script that uses ctypes and openssl to sign
# router descriptors and extrainfo documents and put all the keys in
# the right places.  There are examples at the end of the file.

# I've used this to make inputs for unit tests.  I wouldn't suggest
# using it for anything else.

import base64
import binascii
import ctypes
import ctypes.util
import hashlib

crypt = ctypes.CDLL(ctypes.util.find_library('crypto'))
BIO_s_mem = crypt.BIO_s_mem
BIO_s_mem.argtypes = []
BIO_s_mem.restype = ctypes.c_void_p

BIO_new = crypt.BIO_new
BIO_new.argtypes = [ctypes.c_void_p]
BIO_new.restype = ctypes.c_void_p

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

def b64(x):
    x = base64.b64encode(x)
    res = []
    for i in xrange(0, len(x), 64):
        res.append(x[i:i+64]+"\n")
    return "".join(res)

def bio_extract(bio):
    buf = ctypes.c_char_p()
    length = crypt.BIO_ctrl(bio, 3, 0, ctypes.byref(buf))
    return ctypes.string_at(buf, length)

def make_key(e=65537):
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

    return (rsa,pem,digest)

def signdesc(body, args_out=None):
    rsa, ident_pem, id_digest = make_key()
    _, onion_pem, _ = make_key()

    hexdigest = binascii.b2a_hex(id_digest).upper()
    fingerprint = " ".join(hexdigest[i:i+4] for i in range(0,len(hexdigest),4))

    MAGIC = "<<<<<<MAGIC>>>>>>"
    args = {
        "RSA-IDENTITY" : ident_pem,
        "ONION-KEY" : onion_pem,
        "FINGERPRINT" : fingerprint,
        "FINGERPRINT-NOSPACE" : hexdigest,
        "RSA-SIGNATURE" : MAGIC
    }
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

def emit_ri(name, body, args_out=None):
    print "const char %s[] ="%name
    body = "\n".join(line.rstrip() for line in body.split("\n"))+"\n"
    b = signdesc(body, args_out)
    for line in b.split("\n"):
        print '  "%s\\n"'%line
    print "  ;"

def emit_ei(name, body):
    args = { 'NAME' : name }
    emit_ri(name, body, args)
    args['key'] = "\n".join(
        '  "%s\\n"'%line for line in args['RSA-IDENTITY'].split("\n"))
    print """
const char {NAME}_fp[] = "{FINGERPRINT-NOSPACE}";
const char {NAME}_key[] =
{key};""".format(**args)

if 0:
    emit_ri("minimal",
     """\
router fred 127.0.0.1 9001 0 9002
signing-key
{RSA-IDENTITY}
onion-key
{ONION-KEY}
published 2014-10-05 12:00:00
bandwidth 1000 1000 1000
reject *:*
router-signature
{RSA-SIGNATURE}
""")

if 0:
    emit_ri("maximal",
     """\
router fred 127.0.0.1 9001 0 9002
signing-key
{RSA-IDENTITY}
onion-key
{ONION-KEY}
published 2014-10-05 12:00:00
bandwidth 1000 1000 1000
reject 127.0.0.1:*
accept *:80
reject *:*
ipv6-policy accept 80,100,101
ntor-onion-key s7rSohmz9SXn8WWh1EefTHIsWePthsEntQi0WL+ScVw
uptime 1000
hibernating 0
unrecognized-keywords are just dandy in this format
platform Tor 0.2.4.23 on a Banana PC Jr 6000 Series
contact O.W.Jones
fingerprint {FINGERPRINT}
read-history 900 1,2,3,4
write-history 900 1,2,3,4
extra-info-digest AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
hidden-service-dir
allow-single-hop-exits
family $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA $BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
caches-extra-info
or-address [::1:2:3:4]:9999
or-address 127.0.0.99:10000
opt fred is a fine router
router-signature
{RSA-SIGNATURE}
""")

if 0:
    emit_ei("maximal",
"""\
extra-info bob {FINGERPRINT-NOSPACE}
published 2014-10-05 20:07:00
opt foobarbaz
read-history 900 1,2,3
write-history 900 1,2,3
dirreq-v2-ips 1
dirreq-v3-ips 100
dirreq-v3-reqs blahblah
dirreq-v2-share blahblah
dirreq-v3-share blahblah
dirreq-v2-resp djfkdj
dirreq-v3-resp djfkdj
dirreq-v2-direct-dl djfkdj
dirreq-v3-direct-dl djfkdj
dirreq-v2-tunneled-dl djfkdj
dirreq-v3-tunneled-dl djfkdj
dirreq-stats-end foobar
entry-ips jfsdfds
entry-stats-end ksdflkjfdkf
cell-stats-end FOO
cell-processed-cells FOO
cell-queued-cells FOO
cell-time-in-queue FOO
cell-circuits-per-decile FOO
exit-stats-end FOO
exit-kibibytes-written FOO
exit-kibibytes-read FOO
exit-streams-opened FOO
router-signature
{RSA-SIGNATURE}
""")

if 0:
    emit_ei("minimal",
"""\
extra-info bob {FINGERPRINT-NOSPACE}
published 2014-10-05 20:07:00
router-signature
{RSA-SIGNATURE}
""")

