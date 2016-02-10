#!/usr/bin/python

import re
import sys
import copy
import cPickle
import os

class Parser:
  def __init__(self):
    self.calls = {}
    self.definedIn = {}

  def enter_func(self, name):
    if self.infunc and not self.extern and self.calledfns:
      if self.infunc in self.definedIn:
        #print "{}: {} or {}?".format(
        #  self.infunc, self.definedIn[self.infunc], self.module)
        self.definedIn[self.infunc] = 'nil'
      else:
        self.definedIn[self.infunc] = self.module
      self.calls.setdefault(self.infunc, set()).update( self.calledfns )

    self.calledfns = set()
    self.infunc = name
    self.extern = False

  def parse_callgraph_file(self, inp, module):
    self.infunc = None
    self.extern = False
    self.calledfns = set()
    self.module = module

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
    passno = 0
    changed = True
    g = copy.deepcopy(g)
    import random
    while changed:
      passno += 1
      changed = False
      keys = g.keys()
      idx = 0
      for k in keys:
         idx += 1
         print "Pass %d/?: %d/%d\r" %(passno, idx, len(keys)),
         sys.stdout.flush()
         newset = g[k].copy()
         for fn in g[k]:
            newset.update(g.get(fn, set()))
         if len(newset) != len(g[k]):
            g[k].update( newset )
            changed = True

      print

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

def biggest_component(sccs):
  return max(len(c) for c in sccs)

def connection_bottlenecks(callgraph):

  callers = {}
  for fn in callgraph:
    for fn2 in callgraph[fn]:
      callers.setdefault(fn2, set()).add(fn)

  components = strongly_connected_components(callgraph)
  components.sort(key=len)
  big_component_fns = components[-1]
  size = len(big_component_fns)

  function_bottlenecks = fn_results = []

  total = len(big_component_fns)
  idx = 0
  for fn in big_component_fns:
    idx += 1
    print "Pass 1/3: %d/%d\r"%(idx, total),
    sys.stdout.flush()
    cg2 = copy.deepcopy(callgraph)
    del cg2[fn]

    fn_results.append( (size - biggest_component(strongly_connected_components(cg2)), fn) )

  print
  bcf_set = set(big_component_fns)

  call_bottlenecks = fn_results = []
  result_set = set()
  total = len(big_component_fns)
  idx = 0
  for fn in big_component_fns:
    fn_callers = callers[fn].intersection(bcf_set)
    idx += 1
    if len(fn_callers) != 1:
      continue

    print "Pass 2/3: %d/%d\r"%(idx, total),
    sys.stdout.flush()

    caller = fn_callers.pop()
    assert len(fn_callers) == 0
    cg2 = copy.deepcopy(callgraph)
    cg2[caller].remove(fn)

    fn_results.append( (size - biggest_component(strongly_connected_components(cg2)), fn, "called by", caller) )
    result_set.add( (caller, fn) )

  print

  total = len(big_component_fns)
  idx = 0
  for fn in big_component_fns:
    fn_calls = callgraph[fn].intersection(bcf_set)
    idx += 1
    if len(fn_calls) != 1:
      continue

    print "Pass 3/3: %d/%d\r"%(idx, total),
    sys.stdout.flush()

    callee = fn_calls.pop()
    if (fn, callee) in result_set:
      continue

    assert len(fn_calls) == 0
    cg2 = copy.deepcopy(callgraph)
    cg2[fn].remove(callee)

    fn_results.append( (size - biggest_component(strongly_connected_components(cg2)), callee, "called by", fn) )

  print


  return (function_bottlenecks, call_bottlenecks)

if __name__ == '__main__':
    p = Parser()
    for fname in sys.argv[1:]:
      modname = re.sub(r'.*/', '', fname).replace('.callgraph', '.c')
      with open(fname, 'r') as f:
        p.parse_callgraph_file(f, modname)

    sys.stdout.flush()

    print "Building callgraph"
    callgraph = p.extract_callgraph()
    inModule = p.definedIn

    print "Deriving module callgraph"
    modCallgraph = {}
    for fn in callgraph:
      fnMod = inModule[fn]
      for called in callgraph[fn]:
        try:
          calledMod = inModule[called]
        except KeyError:
            continue
        modCallgraph.setdefault(fnMod, set()).add(calledMod)
    del modCallgraph['nil']

    print "Finding strongly connected components"
    sccs = strongly_connected_components(callgraph)

    print "Finding the transitive closure of the callgraph.."
    closure = transitive_closure(callgraph)

    print "Finding bottlenecks..."
    bottlenecks = connection_bottlenecks(callgraph)

    print "Finding module SCCs"
    modSCCS = strongly_connected_components(modCallgraph)

    print "Finding module TC"
    modTC = transitive_closure(modCallgraph)

    print "Finding module bottlenecks"
    modB = connection_bottlenecks(modCallgraph)

    data = {
      'callgraph' : callgraph,
      'sccs' : sccs,
      'closure' : closure,
      'bottlenecks' : bottlenecks,
      'modules' : p.definedIn,
      'modItems' : {
        'callgraph' : modCallgraph,
        'sccs' : modSCCS,
        'closure' : modTC,
        'bottlenecks' : modB,
      }
    }

    with open('callgraph.pkl', 'w') as f:
      cPickle.dump(data, f)



