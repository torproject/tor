#!/usr/bin/python

import binascii
import hashlib
import os
import struct

import donna25519
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Define basic wrappers.

DIGEST_LEN = 32
ENC_KEY_LEN = 32
PUB_KEY_LEN = 32
SEC_KEY_LEN = 32
IDENTITY_LEN = 32

def sha3_256(s):
    d = hashlib.sha3_256(s).digest()
    assert len(d) == DIGEST_LEN
    return d

def shake_256(s):
    # Note: In reality, you wouldn't want to generate more bytes than needed.
    MAX_KEY_BYTES = 1024
    return hashlib.shake_256(s).digest(MAX_KEY_BYTES)

def curve25519(pk, sk):
    assert len(pk) == PUB_KEY_LEN
    assert len(sk) == SEC_KEY_LEN
    private = donna25519.PrivateKey.load(sk)
    public = donna25519.PublicKey(pk)
    return private.do_exchange(public)

def keygen():
    private = donna25519.PrivateKey()
    public = private.get_public()
    return (private.private, public.public)

def aes256_ctr(k, s):
    assert len(k) == ENC_KEY_LEN
    cipher = AES.new(k, AES.MODE_CTR, counter=Counter.new(128, initial_value=0))
    return cipher.encrypt(s)

# Byte-oriented helper.  We use this for decoding keystreams and messages.

class ByteSeq:
    def __init__(self, data):
        self.data = data

    def take(self, n):
        assert n <= len(self.data)
        result = self.data[:n]
        self.data = self.data[n:]
        return result

    def exhausted(self):
        return len(self.data) == 0

    def remaining(self):
        return len(self.data)

# Low-level functions

MAC_KEY_LEN = 32
MAC_LEN = DIGEST_LEN

hash_func = sha3_256

def encapsulate(s):
    """encapsulate `s` with a length prefix.

       We use this whenever we need to avoid message ambiguities in
       cryptographic inputs.
    """
    assert len(s) <= 0xffffffff
    header = b"\0\0\0\0" + struct.pack("!L", len(s))
    assert len(header) == 8
    return header + s

def h(s, tweak):
    return hash_func(encapsulate(tweak) + s)

def mac(s, key, tweak):
    return hash_func(encapsulate(tweak) + encapsulate(key) + s)

def kdf(s, tweak):
    data = shake_256(encapsulate(tweak) + s)
    return ByteSeq(data)

def enc(s, k):
    return aes256_ctr(k, s)

# Tweaked wrappers

PROTOID = b"ntor3-curve25519-sha3_256-1"
T_KDF_PHASE1 = PROTOID + b":kdf_phase1"
T_MAC_PHASE1 = PROTOID + b":msg_mac"
T_KDF_FINAL = PROTOID + b":kdf_final"
T_KEY_SEED = PROTOID + b":key_seed"
T_VERIFY = PROTOID + b":verify"
T_AUTH = PROTOID + b":auth_final"

def kdf_phase1(s):
    return kdf(s, T_KDF_PHASE1)

def kdf_final(s):
    return kdf(s, T_KDF_FINAL)

def mac_phase1(s, key):
    return mac(s, key, T_MAC_PHASE1)

def h_key_seed(s):
    return h(s, T_KEY_SEED)

def h_verify(s):
    return h(s, T_VERIFY)

def h_auth(s):
    return h(s, T_AUTH)

# Handshake.

def client_phase1(msg, verification, B, ID):
    assert len(B) == PUB_KEY_LEN
    assert len(ID) == IDENTITY_LEN

    (x,X) = keygen()
    p(["x", "X"], locals())
    p(["msg", "verification"], locals())
    Bx = curve25519(B, x)
    secret_input_phase1 = Bx + ID + X + B + PROTOID + encapsulate(verification)

    phase1_keys = kdf_phase1(secret_input_phase1)
    enc_key = phase1_keys.take(ENC_KEY_LEN)
    mac_key = phase1_keys.take(MAC_KEY_LEN)
    p(["enc_key", "mac_key"], locals())

    msg_0 = ID + B + X + enc(msg, enc_key)
    mac = mac_phase1(msg_0, mac_key)
    p(["mac"], locals())

    client_handshake = msg_0 + mac
    state = dict(x=x, X=X, B=B, ID=ID, Bx=Bx, mac=mac, verification=verification)

    p(["client_handshake"], locals())

    return (client_handshake, state)

# server.

class Reject(Exception):
    pass

def server_part1(cmsg, verification, b, B, ID):
    assert len(B) == PUB_KEY_LEN
    assert len(ID) == IDENTITY_LEN
    assert len(b) == SEC_KEY_LEN

    if len(cmsg) < (IDENTITY_LEN + PUB_KEY_LEN * 2 + MAC_LEN):
        raise Reject()

    mac_covered_portion = cmsg[0:-MAC_LEN]
    cmsg = ByteSeq(cmsg)
    cmsg_id = cmsg.take(IDENTITY_LEN)
    cmsg_B = cmsg.take(PUB_KEY_LEN)
    cmsg_X = cmsg.take(PUB_KEY_LEN)
    cmsg_msg = cmsg.take(cmsg.remaining() - MAC_LEN)
    cmsg_mac = cmsg.take(MAC_LEN)

    assert cmsg.exhausted()

    # XXXX for real purposes, you would use constant-time checks here
    if cmsg_id != ID or cmsg_B != B:
        raise Reject()

    Xb = curve25519(cmsg_X, b)
    secret_input_phase1 = Xb + ID + cmsg_X + B + PROTOID + encapsulate(verification)

    phase1_keys = kdf_phase1(secret_input_phase1)
    enc_key = phase1_keys.take(ENC_KEY_LEN)
    mac_key = phase1_keys.take(MAC_KEY_LEN)

    mac_received = mac_phase1(mac_covered_portion, mac_key)
    if mac_received != cmsg_mac:
        raise Reject()

    client_msg = enc(cmsg_msg, enc_key)
    state = dict(
        b=b,
        B=B,
        X=cmsg_X,
        mac_received=mac_received,
        Xb=Xb,
        ID=ID,
        verification=verification)

    return (client_msg, state)

def server_part2(state, server_msg):
    X = state['X']
    Xb = state['Xb']
    B = state['B']
    b = state['b']
    ID = state['ID']
    mac_received = state['mac_received']
    verification = state['verification']

    p(["server_msg"], locals())
    
    (y,Y) = keygen()
    p(["y", "Y"], locals())
    Xy = curve25519(X, y)

    secret_input = Xy + Xb + ID + B + X + Y + PROTOID + encapsulate(verification)
    key_seed = h_key_seed(secret_input)
    verify = h_verify(secret_input)
    p(["key_seed", "verify"], locals())

    keys = kdf_final(key_seed)
    server_enc_key = keys.take(ENC_KEY_LEN)
    p(["server_enc_key"], locals())

    smsg_msg = enc(server_msg, server_enc_key)

    auth_input = verify + ID + B + Y + X + mac_received + encapsulate(smsg_msg) + PROTOID + b"Server"

    auth = h_auth(auth_input)
    server_handshake = Y + auth + smsg_msg
    p(["auth", "server_handshake"], locals())

    return (server_handshake, keys)

def client_phase2(state, smsg):
    x = state['x']
    X = state['X']
    B = state['B']
    ID = state['ID']
    Bx = state['Bx']
    mac_sent = state['mac']
    verification = state['verification']

    if len(smsg) < PUB_KEY_LEN + DIGEST_LEN:
        raise Reject()

    smsg = ByteSeq(smsg)
    Y = smsg.take(PUB_KEY_LEN)
    auth_received = smsg.take(DIGEST_LEN)
    server_msg = smsg.take(smsg.remaining())

    Yx = curve25519(Y,x)

    secret_input = Yx + Bx + ID + B + X + Y + PROTOID + encapsulate(verification)
    key_seed = h_key_seed(secret_input)
    verify = h_verify(secret_input)

    auth_input = verify + ID + B + Y + X + mac_sent + encapsulate(server_msg) + PROTOID + b"Server"

    auth = h_auth(auth_input)
    if auth != auth_received:
        raise Reject()

    keys = kdf_final(key_seed)
    enc_key = keys.take(ENC_KEY_LEN)

    server_msg_decrypted = enc(server_msg, enc_key)

    return (keys, server_msg_decrypted)

def p(varnames, localvars):
    for v in varnames:
        label = v
        val = localvars[label]
        print('{} = "{}"'.format(label, binascii.b2a_hex(val).decode("ascii")))

def test():
    (b,B) = keygen()
    ID = os.urandom(IDENTITY_LEN)

    p(["b", "B", "ID"], locals())

    print("# ============")
    (c_handshake, c_state) = client_phase1(b"hello world", b"xyzzy", B, ID)

    print("# ============")

    (c_msg_got, s_state) = server_part1(c_handshake, b"xyzzy", b, B, ID)

    #print(repr(c_msg_got))

    (s_handshake, s_keys) = server_part2(s_state, b"Hola Mundo")

    print("# ============")

    (c_keys, s_msg_got) = client_phase2(c_state, s_handshake)

    #print(repr(s_msg_got))

    c_keys_256 = c_keys.take(256)
    p(["c_keys_256"], locals())

    assert (c_keys_256 == s_keys.take(256))


if __name__ == '__main__':
    test()
