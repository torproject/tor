#!/usr/bin/python

import cPickle

callgraph = cPickle.load(open("callgraph.cp"))
closure = cPickle.load(open("callgraph_closure.cp"))

for n_reachable, fn in sorted(list((len(r), fn) for fn, r in closure.iteritems())):
   print "%s can reach %s other functions." %(fn, n_reachable)
