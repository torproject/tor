#!/usr/bin/python

import re
import sys
import copy
import cPickle
import os

class Parser:
  def __init__(self):
    self.calls = {}

  def enter_func(self, name):
    if self.infunc and not self.extern:
      self.calls.setdefault(self.infunc, set()).update( self.calledfns )
 
    self.calledfns = set()
    self.infunc = name
    self.extern = False

  def parse_callgraph_file(self, inp):
    self.infunc = None
    self.extern = False
    self.calledfns = set()
    for line in inp:
       m = re.match(r"Call graph node for function: '([^']+)'", line) 
       if m:
           self.enter_func(m.group(1))
           continue
       m = re.match(r"  CS<[^>]+> calls external node", line)
       if m:
           self.extern = True
       m = re.match(r"  CS<[^>]+> calls function '([^']+)'", line)
       if m:
           self.calledfns.add(m.group(1)) 
    self.enter_func(None)

  def extract_callgraph(self):
    c = self.calls
    self.calls = {}
    return c


def transitive_closure(g):
    changed = True
    g = copy.deepcopy(g)
    while changed:
      changed = False
      print "X"
      for k in g.keys():
         newset = g[k].copy()
         for fn in g[k]:
            newset.update(g.get(fn, set()))
         if len(newset) != len(g[k]):
            g[k].update( newset )
            changed = True
    return g

if __name__ == '__main__':
    p = Parser()
    for fname in sys.argv[1:]:
      with open(fname, 'r') as f:
        p.parse_callgraph_file(f)
    callgraph = p.extract_callgraph()

    closure = transitive_closure(callgraph)

    with open('callgraph.cp', 'w') as f:
      cPickle.dump(callgraph, f)

    with open('callgraph_closure.cp', 'w') as f:
      cPickle.dump(closure, f)
