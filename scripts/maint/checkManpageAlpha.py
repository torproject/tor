#!/usr/bin/python

import difflib
import re
import sys

# Assume we only use the "== Section Name" section title syntax
sectionheader_re = re.compile(r'^==+\s(.*)\s*$')

# Assume we only use the "[[ItemName]]" anchor syntax
anchor_re = re.compile(r'^\[\[([^]]+)\]\]')

class Reader(object):
    def __init__(self):
        self.d = {}
        # Initial state is to gather section headers
        self.getline = self._getsec
        self.section = None

    def _getsec(self, line):
        """Read a section header

        Prepare to gather anchors from subsequent lines.  Don't change
        state if the line isn't a section header.
        """
        m = sectionheader_re.match(line)
        if not m:
            return
        self.anchors = anchors = []
        self.d[m.group(1)] = anchors
        self.getline = self._getanchor

    def _getanchor(self, line):
        """Read an anchor for an item definition

        Append the anchor names to the list of items in the current
        section.
        """
        m = anchor_re.match(line)
        if not m:
            return self._getsec(line)
        self.anchors.append(m.group(1))

    def diffsort(self, key):
        """Unified diff of unsorted and sorted item lists
        """
        # Append newlines because difflib works better with them
        a = [s + '\n' for s in self.d[key]]
        b = sorted(a, key=str.lower)
        return difflib.unified_diff(a, b, fromfile=key+' unsorted',
                                    tofile=key+' sorted')

def main():
    """Diff unsorted and sorted lists of option names in a manpage

    Use the file named by the first argument, or standard input if
    there is none.
    """
    try:
        fname = sys.argv[1]
        f = open(fname, 'r')
    except IndexError:
        f = sys.stdin

    reader = Reader()
    for line in f:
        reader.getline(line)
    for key in sorted(reader.d.keys(), key=str.lower):
        sys.stdout.writelines(reader.diffsort(key))

if __name__ == '__main__':
    main()
