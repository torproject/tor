#!/usr/bin/env python3
# Copyright 2018-2019, The Tor Project, Inc. See LICENSE for licensing info.

# Reference implementation for our rudimentary OPE code, used to
# generate test vectors. See crypto_ope.c for more details.

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.backends import default_backend

from binascii import a2b_hex

#randomly generated and values.
KEY = a2b_hex(
    "19e05891d55232c08c2cad91d612fdb9cbd6691949a0742434a76c80bc6992fe")
PTS = [ 121132, 82283, 72661, 72941, 123122, 12154, 121574, 11391, 65845,
        86301, 61284, 70505, 30438, 60150, 114800, 109403, 21893, 123569,
        95617, 48561, 53334, 92746, 7110, 9612, 106958, 46889, 87790, 68878,
        47917, 121128, 108602, 28217, 69498, 63870, 57542, 122148, 46254,
        42850, 92661, 57720]

IV = b'\x00' * 16

backend = default_backend()

def words():
    cipher = Cipher(algorithms.AES(KEY), modes.CTR(IV), backend=backend)
    e = cipher.encryptor()
    while True:
        v = e.update(b'\x00\x00')
        yield v[0] + 256 * v[1] + 1

def encrypt(n):
    return sum(w for w, _ in zip(words(), range(n)))

def example(n):
    return ' {{ {}, UINT64_C({}) }},'.format(n, encrypt(n))

for v in PTS:
    print(example(v))
