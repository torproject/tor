#!/usr/bin/python

import cPickle

callgraph = cPickle.load(open("callgraph.pkl"))
closure = cPickle.load(open("callgraph_closure.pkl"))
sccs = cPickle.load(open("callgraph_sccs.pkl"))

for n_reachable, fn in sorted(list((len(r), fn) for fn, r in closure.iteritems())):
   print "%s can reach %s other functions." %(fn, n_reachable)


c = [ (len(component), component) for component in sccs ]
c.sort()

for n, component in c:
   if n < 2:
      continue
   print n, component



