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

def strongly_connected_components(g):
  # From https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm, done stupidly.
  index_of = {}
  index = [ 0 ]
  lowlink = {}
  S = []
  onStack = set()

  all_sccs = []

  def strongconnect(fn):
    index_of[fn] = index[0]
    lowlink[fn] = index[0]
    index[0] += 1
    S.append(fn)
    onStack.add(fn)

    for w in g.get(fn, []):
      if w not in index_of:
        strongconnect(w)
        lowlink[fn] = min(lowlink[fn], lowlink[w])
      elif w in onStack:
        lowlink[fn] = min(lowlink[fn], index_of[w])

    if lowlink[fn] == index_of[fn]:
      this_scc = []
      all_sccs.append(this_scc)
      while True:
        w = S.pop()
        onStack.remove(w)
        this_scc.append(w)
        if w == fn:
          break

  for v in g.keys():
    if v not in index_of:
      strongconnect(v)

  return all_sccs

if __name__ == '__main__':
    p = Parser()
    for fname in sys.argv[1:]:
      with open(fname, 'r') as f:
        p.parse_callgraph_file(f)
    callgraph = p.extract_callgraph()

    sccs = strongly_connected_components(callgraph)

    closure = transitive_closure(callgraph)

    with open('callgraph.pkl', 'w') as f:
      cPickle.dump(callgraph, f)

    with open('callgraph_closure.pkl', 'w') as f:
      cPickle.dump(closure, f)

    with open('callgraph_sccs.pkl', 'w') as f:
      cPickle.dump(sccs, f)
