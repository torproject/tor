# This is a reference implementation of the SRV calculation for prop250. We
# use it to generate a test vector for the test_sr_compute_srv() unittest.
# (./test shared-random/sr_compute_srv)
#
# Here is the SRV computation formula:
#
#      HASHED_REVEALS = H(ID_a | R_a | ID_b | R_b | ..)
#
#      SRV = SHA3-256("shared-random" | INT_8(reveal_num) | INT_4(version) |
#                     HASHED_REVEALS | previous_SRV)
#

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import hashlib
import struct

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

# In this example, we use three reveal values.
reveal_num = 3
version = 1

# We set directly the ascii value because memset(buf, 'A', 20) makes it to 20
# times "41" in the final string.

# Identity and reveal value of dirauth a
ID_a = 20 * "41" # RSA identity of 40 base16 bytes.
R_a = 56 * 'A' # 56 base64 characters

# Identity and reveal value of dirauth b
ID_b = 20 * "42" # RSA identity of 40 base16 bytes.
R_b = 56 * 'B' # 56 base64 characters

# Identity and reveal value of dirauth c
ID_c = 20 * "43" # RSA identity of 40 base16 bytes.
R_c = 56 * 'C' # 56 base64 characters

# Concatenate them all together and hash them to form HASHED_REVEALS.
REVEALS = (ID_a + R_a + ID_b + R_b + ID_c + R_c).encode()
hashed_reveals_object = hashlib.sha3_256(REVEALS)
hashed_reveals = hashed_reveals_object.digest()

previous_SRV = (32 * 'Z').encode()

# Now form the message.
#srv_msg = struct.pack('13sQL256ss', "shared-random", reveal_num, version,
#                      hashed_reveals, previous_SRV)
invariant_token = b"shared-random"
srv_msg = invariant_token + \
          struct.pack('!QL', reveal_num, version) + \
          hashed_reveals + \
          previous_SRV

# Now calculate the HMAC
srv = hashlib.sha3_256(srv_msg)
print("%s" % srv.hexdigest().upper())

# 2A9B1D6237DAB312A40F575DA85C147663E7ED3F80E9555395F15B515C74253D 
