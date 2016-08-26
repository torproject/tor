# This is a reference implementation of the COMMIT/REVEAL calculation for
# prop250. We use it to generate a test vector for the test_encoding()
# unittest.
#
# Here is the computation formula:
#
#      H = SHA3-256
#      TIMESTAMP = 8 bytes network-endian value
#      RAND = H(32 bytes of random)
#
#      REVEAL = base64-encode( TIMESTAMP || RAND )
#      COMMIT = base64-encode( TIMESTAMP || H(REVEAL) )
#

import sys
import hashlib
import struct
import base64

# Python 3.6+, the SHA3 is available in hashlib natively. Else this requires
# the pysha3 package (pip install pysha3).
if sys.version_info < (3, 6):
	import sha3

# Test vector to make sure the right sha3 version will be used. pysha3 < 1.0
# used the old Keccak implementation. During the finalization of SHA3, NIST
# changed the delimiter suffix from 0x01 to 0x06. The Keccak sponge function
# stayed the same. pysha3 1.0 provides the previous Keccak hash, too.
TEST_VALUE = "e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51"
if TEST_VALUE != sha3.sha3_256(b"Hello World").hexdigest():
  print("pysha3 version is < 1.0. Please install from:")
  print("https://github.com/tiran/pysha3https://github.com/tiran/pysha3")
  sys.exit(1)

# TIMESTAMP
ts = 1454333590
# RAND
data = 'A' * 32 # Yes very very random, NIST grade :).
rand = hashlib.sha3_256(data)

reveal = struct.pack('!Q', ts) + rand.digest()
b64_reveal = base64.b64encode(reveal)
print("REVEAL: %s" % (b64_reveal))

# Yes we do hash the _encoded_ reveal here that is H(REVEAL)
hashed_reveal = hashlib.sha3_256(b64_reveal)
commit = struct.pack('!Q', ts) + hashed_reveal.digest()
print("COMMIT: %s" % (base64.b64encode(commit)))

# REVEAL: AAAAAFavXpZJxbwTupvaJCTeIUCQmOPxAMblc7ChL5H2nZKuGchdaA==
# COMMIT: AAAAAFavXpbkBMzMQG7aNoaGLFNpm2Wkk1ozXhuWWqL//GynltxVAg==
