@dir /feature/dirparse
@brief feature/dirparse: Parsing Tor directory objects

We define a number of "directory objects" in
[dir-spec.txt](https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt),
all of them using a common line-oriented meta-format.  This module is used by
other parts of Tor to parse them.

