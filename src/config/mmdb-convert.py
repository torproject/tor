#!/usr/bin/python3

#   This software has been dedicated to the public domain under the CC0
#   public domain dedication.
#
#   To the extent possible under law, the person who associated CC0
#   with mmdb-convert.py has waived all copyright and related or
#   neighboring rights to mmdb-convert.py.
#
#   You should have received a copy of the CC0 legalcode along with this
#   work in doc/cc0.txt.  If not, see
#      <http://creativecommons.org/publicdomain/zero/1.0/>.

#  Nick Mathewson is responsible for this kludge, but takes no
#  responsibility for it.

"""This kludge is meant to
   parse mmdb files in sufficient detail to dump out the old format
   that Tor expects.  It's also meant to be pure-python.

   When given a simplicity/speed tradeoff, it opts for simplicity.

   You will not understand the code without undestanding the MaxMind-DB
   file format.  It is specified at:
   https://github.com/maxmind/MaxMind-DB/blob/master/MaxMind-DB-spec.md.

   This isn't so much tested.  When it breaks, you get to keep both
   pieces.
"""

import struct
import bisect
import socket
import binascii
import sys
import time

METADATA_MARKER = b'\xab\xcd\xefMaxMind.com'

# Here's some python2/python3 junk.  Better solutions wanted.
try:
    ord(b"1"[0])
except TypeError:
    def byte_to_int(b):
        "convert a single element of a bytestring to an integer."
        return b
else:
    byte_to_int = ord

# Here's some more python2/python3 junk.  Better solutions wanted.
try:
    str(b"a", "utf8")
except TypeError:
    bytesToStr = str
else:
    def bytesToStr(b):
        "convert a bytestring in utf8 to a string."
        return str(b, 'utf8')

def to_int(s):
    "Parse a big-endian integer from bytestring s."
    result = 0
    for c in s:
        result *= 256
        result += byte_to_int(c)
    return result

def to_int24(s):
    "Parse a pair of big-endian 24-bit integers from bytestring s."
    a, b, c = struct.unpack("!HHH", s)
    return ((a <<8)+(b>>8)), (((b&0xff)<<16)+c)

def to_int32(s):
    "Parse a pair of big-endian 32-bit integers from bytestring s."
    a, b = struct.unpack("!LL", s)
    return a, b

def to_int28(s):
    "Parse a pair of big-endian 28-bit integers from bytestring s."
    a, b = unpack("!LL", s + b'\x00')
    return (((a & 0xf0) << 20) + (a >> 8)), ((a & 0x0f) << 24) + (b >> 8)

class Tree(object):
    "Holds a node in the tree"
    def __init__(self, left, right):
        self.left = left
        self.right = right

def resolve_tree(tree, data):
    """Fill in the left_item and right_item fields for all values in the tree
       so that they point to another Tree, or to a Datum, or to None."""
    d = Datum(None, None, None, None)
    def resolve_item(item):
        "Helper: resolve a single index."
        if item < len(tree):
            return tree[item]
        elif item == len(tree):
            return None
        else:
            d.pos = (item - len(tree) - 16)
            p = bisect.bisect_left(data, d)
            assert data[p].pos == d.pos
            return data[p]

    for t in tree:
        t.left_item = resolve_item(t.left)
        t.right_item = resolve_item(t.right)

def parse_search_tree(s, record_size):
    """Given a bytestring and a record size in bits, parse the tree.
       Return a list of nodes."""
    record_bytes = (record_size*2) // 8
    nodes = []
    p = 0
    try:
        to_leftright = { 24: to_int24,
                         28: to_int28,
                         32: to_int32 }[ record_size ]
    except KeyError:
        raise NotImplementedError("Unsupported record size in bits: %d" %
                                  record_size)
    while p < len(s):
        left, right = to_leftright(s[p:p+record_bytes])
        p += record_bytes

        nodes.append( Tree(left, right ) )

    return nodes

class Datum(object):
    """Holds a single entry from the Data section"""
    def __init__(self, pos, kind, ln, data):
        self.pos = pos    # Position of this record within data section
        self.kind = kind  # Type of this record. one of TP_*
        self.ln = ln      # Length field, which might be overloaded.
        self.data = data  # Raw bytes data.
        self.children = None # Used for arrays and maps.

    def __repr__(self):
        return "Datum(%r,%r,%r,%r)" % (self.pos, self.kind, self.ln, self.data)

    # Comparison functions used for bsearch
    def __lt__(self, other):
        return self.pos < other.pos

    def __gt__(self, other):
        return self.pos > other.pos

    def __eq__(self, other):
        return self.pos == other.pos

    def build_maps(self):
        """If this is a map or array, fill in its 'map' field if it's a map,
           and the 'map' field of all its children."""

        if not hasattr(self, 'nChildren'):
            return

        if self.kind == TP_ARRAY:
            del self.nChildren
            for c in self.children:
                c.build_maps()

        elif self.kind == TP_MAP:
            del self.nChildren
            self.map = {}
            for i in range(0, len(self.children), 2):
                k = self.children[i].deref()
                v = self.children[i+1].deref()
                v.build_maps()
                if k.kind != TP_UTF8:
                    raise ValueError("Bad dictionary key type %d"% k.kind)
                self.map[bytesToStr(k.data)] = v

    def int_val(self):
        """If this is an integer type, return its value"""
        assert self.kind in (TP_UINT16, TP_UINT32, TP_UINT64,
                             TP_UINT128, TP_SINT32)
        i = to_int(self.data)
        if self.kind == TP_SINT32:
            if i & 0x80000000:
                i = i - 0x100000000
        return i

    def deref(self):
        """If this value is a pointer, return its pointed-to-value.  Chase
           through multiple layers of pointers if need be.  If this isn't
           a pointer, return it."""
        n = 0
        s = self
        while s.kind == TP_PTR:
            s = s.ptr
            n += 1
            assert n < 100
        return s

def resolve_pointers(data):
    """Fill in the ptr field of every pointer in data."""
    search = Datum(None, None, None, None)
    for d in data:
        if d.kind == TP_PTR:
            search.pos = d.ln
            p = bisect.bisect_left(data, search)
            assert data[p].pos == d.ln
            d.ptr = data[p]

TP_PTR = 1
TP_UTF8 = 2
TP_DBL = 3
TP_BYTES = 4
TP_UINT16 = 5
TP_UINT32 = 6
TP_MAP = 7
TP_SINT32 = 8
TP_UINT64 = 9
TP_UINT128 = 10
TP_ARRAY = 11
TP_DCACHE = 12
TP_END = 13
TP_BOOL = 14
TP_FLOAT = 15

def get_type_and_len(s):
    """Data parsing helper: decode the type value and much-overloaded 'length'
       field for the value starting at s.  Return a 3-tuple of type, length,
       and number of bytes used to encode type-plus-length."""
    c = byte_to_int(s[0])
    tp = c >> 5
    skip = 1
    if tp == 0:
        tp = byte_to_int(s[1])+7
        skip = 2
    ln = c & 31

    # I'm sure I don't know what they were thinking here...
    if tp == TP_PTR:
        len_len = (ln >> 3) + 1
        if len_len < 4:
            ln &= 7
            ln <<= len_len * 8
        else:
            ln = 0
        ln += to_int(s[skip:skip+len_len])
        ln += (0, 0, 2048, 526336, 0)[len_len]
        skip += len_len
    elif ln >= 29:
        len_len = ln - 28
        ln = to_int(s[skip:skip+len_len])
        ln += (0, 29, 285, 65821)[len_len]
        skip += len_len

    return tp, ln, skip

# Set of types for which 'length' doesn't mean length.
IGNORE_LEN_TYPES = set([
    TP_MAP,    # Length is number of key-value pairs that follow.
    TP_ARRAY,  # Length is number of members that follow.
    TP_PTR,    # Length is index to pointed-to data element.
    TP_BOOL,   # Length is 0 or 1.
    TP_DCACHE, # Length isnumber of members that follow
])

def parse_data_section(s):
    """Given a data section encoded in a bytestring, return a list of
       Datum items."""

    # Stack of possibly nested containers.  We use the 'nChildren' member of
    # the last one to tell how many moreitems nest directly inside.
    stack = []

    # List of all items, including nested ones.
    data = []

    # Byte index within the data section.
    pos = 0

    while s:
        tp, ln, skip = get_type_and_len(s)
        if tp in IGNORE_LEN_TYPES:
            real_len = 0
        else:
            real_len = ln

        d = Datum(pos, tp, ln, s[skip:skip+real_len])
        data.append(d)
        pos += skip+real_len
        s = s[skip+real_len:]

        if stack:
            stack[-1].children.append(d)
            stack[-1].nChildren -= 1
            if stack[-1].nChildren == 0:
                del stack[-1]

        if d.kind == TP_ARRAY:
            d.nChildren = d.ln
            d.children = []
            stack.append(d)
        elif d.kind == TP_MAP:
            d.nChildren = d.ln * 2
            d.children = []
            stack.append(d)

    return data

def parse_mm_file(s):
    """Parse a MaxMind-DB file."""
    try:
        metadata_ptr = s.rindex(METADATA_MARKER)
    except ValueError:
        raise ValueError("No metadata!")

    metadata = parse_data_section(s[metadata_ptr+len(METADATA_MARKER):])

    if metadata[0].kind != TP_MAP:
        raise ValueError("Bad map")

    metadata[0].build_maps()
    mm = metadata[0].map

    tree_size = (((mm['record_size'].int_val() * 2) // 8 ) *
                 mm['node_count'].int_val())

    if s[tree_size:tree_size+16] != b'\x00'*16:
        raise ValueError("Missing section separator!")

    tree = parse_search_tree(s[:tree_size], mm['record_size'].int_val())

    data = parse_data_section(s[tree_size+16:metadata_ptr])

    resolve_pointers(data)
    resolve_tree(tree, data)

    for d in data:
        d.build_maps()

    return metadata, tree, data

def format_datum(datum):
    """Given a Datum at a leaf of the tree, return the string that we should
       write as its value.
    """
    try:
        return bytesToStr(datum.map['country'].map['iso_code'].data)
    except KeyError:
        pass
    return None

IPV4_PREFIX = "0"*96

def dump_item_ipv4(entries, prefix, val):
    """Dump the information for an IPv4 address to entries, where 'prefix'
       is a string holding a binary prefix for the address, and 'val' is the
       value to dump.  If the prefix is not an IPv4 address (it does not start
       with 96 bits of 0), then print nothing.
    """
    if not prefix.startswith(IPV4_PREFIX):
        return
    prefix = prefix[96:]
    v = int(prefix, 2)
    shift = 32 - len(prefix)
    lo = v << shift
    hi = ((v+1) << shift) - 1
    entries.append((lo, hi, val))

def fmt_item_ipv4(entry):
    """Format an IPv4 range with lo and hi addresses in decimal form."""
    return "%d,%d,%s\n"%(entry[0], entry[1], entry[2])

def fmt_ipv6_addr(v):
    """Given a 128-bit integer representing an ipv6 address, return a
       string for that ipv6 address."""
    return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify("%032x"%v))

def fmt_item_ipv6(entry):
    """Format an IPv6 range with lo and hi addresses in hex form."""
    return "%s,%s,%s\n"%(fmt_ipv6_addr(entry[0]),
                         fmt_ipv6_addr(entry[1]),
                         entry[2])

IPV4_MAPPED_IPV6_PREFIX = "0"*80 + "1"*16
IPV6_6TO4_PREFIX = "0010000000000010"

def dump_item_ipv6(entries, prefix, val):
    """Dump the information for an IPv6 address prefix to entries, where
       'prefix' is a string holding a binary prefix for the address,
       and 'val' is the value to dump.  If the prefix is an IPv4 address
       (starts with 96 bits of 0), is an IPv4-mapped IPv6 address
       (::ffff:0:0/96), or is in the 6to4 mapping subnet (2002::/16), then
       print nothing.
    """
    if prefix.startswith(IPV4_PREFIX) or \
       prefix.startswith(IPV4_MAPPED_IPV6_PREFIX) or \
       prefix.startswith(IPV6_6TO4_PREFIX):
        return
    v = int(prefix, 2)
    shift = 128 - len(prefix)
    lo = v << shift
    hi = ((v+1) << shift) - 1
    entries.append((lo, hi, val))

def dump_tree(entries, node, dump_item, prefix=""):
    """Walk the tree rooted at 'node', and call dump_item on the
       format_datum output of every leaf of the tree."""

    if isinstance(node, Tree):
        dump_tree(entries, node.left_item, dump_item, prefix+"0")
        dump_tree(entries, node.right_item, dump_item, prefix+"1")
    elif isinstance(node, Datum):
        assert node.kind == TP_MAP
        code = format_datum(node)
        if code:
            dump_item(entries, prefix, code)
    else:
        assert node == None

def write_geoip_file(filename, metadata, the_tree, dump_item, fmt_item):
    """Write the entries in the_tree to filename."""
    entries = []
    dump_tree(entries, the_tree[0], dump_item)
    fobj = open(filename, 'w')

    build_epoch = metadata[0].map['build_epoch'].int_val()
    fobj.write("# Last updated based on %s Maxmind GeoLite2 Country\n"%
               time.strftime('%B %-d %Y', time.gmtime(build_epoch)))

    unwritten = None
    for entry in entries:
        if not unwritten:
            unwritten = entry
        elif unwritten[1] + 1 == entry[0] and unwritten[2] == entry[2]:
            unwritten = (unwritten[0], entry[1], unwritten[2])
        else:
            fobj.write(fmt_item(unwritten))
            unwritten = entry
    if unwritten:
        fobj.write(fmt_item(unwritten))
    fobj.close()

content = open(sys.argv[1], 'rb').read()
metadata, the_tree, _ = parse_mm_file(content)

write_geoip_file('geoip', metadata, the_tree, dump_item_ipv4, fmt_item_ipv4)
write_geoip_file('geoip6', metadata, the_tree, dump_item_ipv6, fmt_item_ipv6)
