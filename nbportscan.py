#!/usr/bin/env python
#
# nbportscan.py - Copyright(c) 2014 - Krister Hedfors
#
# A minimalistic and fast non-blocking TCP port scanner.
#
# Usage:
# $ python nbportscan.py <ip-or-range> <port-or-range> ...
#
# Example:
# $ python nbportscan.py 10.0.0.1-255 21-23 25 80 8080
#
#
# Limitations:
# IP range notation is only allowed for the last octet in IP-address.
# The first arg MUST be an IP or IP-range, ALL following arguments
# are treated as ports or port-ranges.
#
from socket import *
import sys
import time
import re


TIMEOUT = 3
PARALLELISM = 100
h_in, p_in = sys.argv[1], sys.argv[2:]
hosts = []
ports = []
res = []
active = {}


for pp in p_in:
    for p in pp.split():
        if '-' in p:
            a, b = p.split('-', 1)
            ports += range(int(a), int(b) + 1)
        else:
            ports += [int(p)]

for h in h_in.split():
    m = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', h)
    if m:
        for i in xrange(int(m.group(2)), int(m.group(3)) + 1):
            hosts.append(m.group(1) + str(i))
        continue
    m = re.match(r'^(\d+\.\d+\.\d+\.)\*$', h)
    if m:
        for i in xrange(1, 255):
            hosts.append(m.group(1) + str(i))
        continue
    hosts.append(h)


def process(res):
    for (a, st) in active.copy().iteritems():
        s, t = st
        cont = 0
        try:
            s.connect(a)
        except error, e:
            if 'progress' in str(e):
                if time.time() - t < TIMEOUT:
                    cont = 1
                else:
                    res.append((a, 'filtered'))
            elif 'refused' in str(e):
                res.append((a, 'closed'))
            elif 'timed out' in str(e):
                res.append((a, 'filtered'))
            else:
                raise
        else:
            res.append((a, 'open'))
        if not cont:
            s.close()
            del active[a]
    time.sleep(0.1)

for h in hosts:
    for p in ports:
        a = (h, p)
        if len(active) < PARALLELISM:
            s = socket(AF_INET, SOCK_STREAM)
            s.setblocking(0)
            active[a] = (s, time.time())
            continue
        process(res)


while active:
    process(res)

for r in sorted(res, key=lambda t: (t[0][1], t[0][0])):
    print r[0][0], r[0][1], r[1]
