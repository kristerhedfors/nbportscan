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
PARALLELISM = 512
hosts = []
ports = []
res = []
active = {}


for x in sys.argv[1:]:
    if x.isdigit():
        ports += [int(x)]
    elif x.replace('-', '').isdigit():
        a, b = x.split('-', 1)
        ports += range(int(a), int(b) + 1)
    else:
        m = re.match(r'^(\d+\.\d+\.\d+\.)(\d+|(\d+)-(\d+)|\*)$', x)
        if m.group(2).isdigit():
            a = int(m.group(2))
            b = a + 1
        elif m.group(3):
            a = int(m.group(3))
            b = int(m.group(4)) + 1
        elif m.group(2) == '*':
            a = 0
            b = 256
        for d in range(a, b):
            hosts.append(m.group(1) + str(d))


def _laddr(s):
    try:
        return s.getsockname()
    except:
        return 'nolocalip'


def process(res):
    for (a, st) in active.copy().iteritems():
        s, t = st
        cont = 0
        try:
            s.connect(a)
        except error, e:
            _la = _laddr(s)
            if 'progress' in str(e):
                if time.time() - t < TIMEOUT:
                    cont = 1
                else:
                    res.append((_la, a, 'filtered'))
            elif 'refused' in str(e).lower():
                res.append((_la, a, 'closed'))
            elif 'timed out' in str(e).lower():
                res.append((_la, a, 'filtered'))
            else:
                m = re.match(r'.*[^\w\s]([\w\s]+)[^\w]*$', str(e))
                if m:
                    err = m.group(1).lower().strip().replace(' ', '-')
                    res.append((_la, a, err))
                else:
                    raise
        else:
            res.append((_laddr(s), a, 'open'))
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


for r in sorted(res, key=lambda t: (t[1][0], t[1][1])):
    #print r[0][0], r[0][1], '->', r[1][0], r[1][1], r[2]
    print r[0][0], '->', r[1][0], r[1][1], r[2]
