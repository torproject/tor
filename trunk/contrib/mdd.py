#!/usr/bin/env python2.3

import re, sys
import textwrap

files = sys.argv[1:]
funcDeclaredIn = {}
fileDeclares = {}
functionCalls = {}
funcCalledByFile = {}
funcCalledByFunc = {}

cpp_re = re.compile(r'//.*$')
c_re = re.compile(r'/[*]+(?:[^*]+|[*]+[^/*])*[*]+/', re.M|re.S)

for fname in files:
    f = open(fname, 'r')
    curFunc = "???"
    functionCalls.setdefault(curFunc,{})
    lineno = 0
    body = f.read()
    body = cpp_re.sub(" ",body)
    body = c_re.sub(" ",body)
    #if fname == 'dns.c': print body
    for line in body.split("\n"):
        lineno += 1
        m = re.match(r'^[^\s/].*\s(\w+)\([^;]*$', line)
        if m:
            #print line, "->", m.group(1)
            curFunc = m.group(1)
            if curFunc[0] == '_': curFunc = curFunc[1:]
            functionCalls.setdefault(curFunc,{})
            funcDeclaredIn[m.group(1)] = fname
            fileDeclares.setdefault(fname, {})[m.group(1)] = 1
            continue
        m = re.match(r'^(\w+)\([^;]', line)
        if m:
            #print line, "->", m.group(1)
            curFunc = m.group(1)
            if curFunc[0] == '_': curFunc = curFunc[1:]
            functionCalls.setdefault(curFunc,{})
            funcDeclaredIn[m.group(1)] = fname
            fileDeclares.setdefault(fname, {})[m.group(1)] = 1
            continue
        while line:
            m = re.search(r'(\w+)\(', line)
            if not m: break
            #print fname, line, curFunc, "->", m.group(1)
            fn = m.group(1)
            if fn[0] == '_':
                fn = fn[1:]
            functionCalls[curFunc][m.group(1)] = 1
            #if curFunc == "???":
            #    print ">>!!!!! at %s:%s"%(fname,lineno)
            funcCalledByFunc.setdefault(m.group(1), {})[curFunc]=1
            funcCalledByFile.setdefault(m.group(1), {})[fname]=1
            line = line[m.end():]

    f.close()

fileUsers = {}
fileUses = {}

for fname in files:
    print "%s:"%fname
    users = {}
    for func in fileDeclares[fname]:
        cb = funcCalledByFile.get(func,{}).keys()
        for f in cb: users[f] = 1
        #print "users[%s] = %s"%(f,users[f])
    users = users.keys()
    users.sort()
    fileUsers[fname] = users
    for user in users:
        fileUses.setdefault(user,[]).append(fname)
        if user == fname: continue
        print "  from %s:"%user
        for func in fileDeclares[fname]:
            if funcCalledByFile.get(func,{}).get(user,0):
                print "    %s()"%func

def wrap(s, pre):
    return textwrap.fill(s,
                         width=77, initial_indent=pre,
                         subsequent_indent=" "*len(pre))

for fname in files:
    print
    print "===== %s"%fname
    print wrap(" ".join(fileUses[fname]),
               "        Calls: ")
    print wrap(" ".join(fileUsers[fname]),
              "    Called by: ")

print "=============================="

funcnames = functionCalls.keys()
funcnames.sort()

if 1:
    for func in funcnames:
        print "===== %s"%func
        callers = [c for c in funcCalledByFunc.get(func,{}).keys()
                   if c != "???"]
        callers.sort()
        called = [c for c in functionCalls[func].keys() if c != "???" and
                  c in funcnames]
        called.sort()
        print wrap(" ".join(callers),
                   "  Called by:")
        print wrap(" ".join(called),
                   "      Calls:")

# simple topological sort.
functionDepth = {}
while 1:
    BIG = 1000000
    any = 0
    for func in funcnames:
        if functionDepth.has_key(func):
            continue
        called = [c for c in functionCalls[func] if c != func and
                  functionCalls.has_key(c)]
        if len(called) == 0:
            functionDepth[func] = 0
            #print "Depth(%s)=%s"%(func,0)
            any = 1
            continue
        calledDepths = [ functionDepth.get(c,BIG) for c in called ]
        if max(calledDepths) < BIG:
            d = functionDepth[func] = max(calledDepths)+1
            #print "Depth(%s)=%s"%(func,d)
            any = 1
            continue
    if not any:
        break

# compute lexical closure.
cycCalls = {}
for func in funcnames:
    if not functionDepth.has_key(func):
        calls = [ c for c in functionCalls[func] if c != func and
                  functionCalls.has_key(c) and not functionDepth.has_key(c)]
        cycCalls[func] = d = {}
        for c in calls:
            d[c]=1

cycNames = cycCalls.keys()
while 1:
    any = 0
    for func in cycNames:
        L = len(cycCalls[func])
        for called in cycCalls[func].keys():
            cycCalls[func].update(cycCalls[called])
        if L != len(cycCalls[func]):
            any = 1
    if not any:
        break

depthList = [ (v,k) for k,v in functionDepth.items() ]
depthList.sort()
cycList = [ (len(v),k) for k,v in cycCalls.items() ]
cycList.sort()
for depth,name in depthList:
    print "Depth[%s]=%s"%(name,depth)
for bredth,name in cycList:
    print "Width[%s]=%s"%(name,bredth)

print "Sorted %s / %s"%(len(functionDepth),len(funcnames))
