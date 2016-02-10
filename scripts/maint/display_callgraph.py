#!/usr/bin/python

import cPickle

data = cPickle.load(open("callgraph.pkl"))

# data = data['modItems']

callgraph = data['callgraph']
closure = data['closure']
sccs = data['sccs']
fn_bottle, call_bottle = data['bottlenecks']

for n_reachable, fn in sorted(list((len(r), fn) for fn, r in closure.iteritems())):
   print "%s can reach %s other functions." %(fn, n_reachable)


c = [ (len(component), component) for component in sccs ]
c.sort()

print "\n================================"

for n, component in c:
   if n < 2:
      continue
   print "Strongly connected component of size %d:"%n
   print component


print "\n================================"

print "====== Number of functions pulled into blob, by function in blob."
fn_bottle.sort()
for n, fn in fn_bottle[-30:]:
   print "%3d: %s"%(n, fn)

print "====== Number of functions pulled into blob, by call in blob."
call_bottle.sort()
for n, fn1, _, fn2 in call_bottle[-30:]:
   print "%3d: %s -> %s "%(n, fn2, fn1)

