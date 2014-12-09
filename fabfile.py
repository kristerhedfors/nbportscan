#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2014 Krister Hedfors
#
#
# Example:
#  Portscan hosta, hostb, hostc (a->a, a->b, a->c, b->a, b->b, ...)
#  on all tcp port numbers listening on at least one of hosta, hostb, hostc:
#
# $ fab -H hosta,hostb,hostc list_open_ports > ports.txt
# $ plist="`grep out:.. ports.txt | cut -d' ' -f4 | sort -nu | tr '\n' ' '`"
# $ fab -H hosta,hostb,hostc portscan:"hosta hostb hostc $plist"
#
# You can also compare the results of two extensive portscans between various
# src and dst addresses using the regular `diff` command.
#

import zlib

from fabric.api import task
from fabric.api import run
from fabric.api import hide
from fabric.tasks import Task


class Portscan(Task):
    '''
    example: fab portscan:"127.0.0.1 10.0.0.2-100 21-23 25 80 443"
    '''
    name = 'portscan'

    def run(self, hosts_and_ports):
        portscanner = open('nbportscan.py').read()
        cmd = 'python -c "{0}" {1}'.format(
            portscanner, hosts_and_ports
        )
        with hide('running'):
            run(cmd)


class ListOpenPorts(Task):
    '''
    show listening TCP-ports
    '''
    name = 'list_open_ports'

    def run(self):
        cmd = "netstat -nlt"
        cmd += r"|sed -rne 's/.* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+).*/\1 \2/p'"
        with hide('running'):
            run(cmd)


portscan = Portscan()
list_open_ports = ListOpenPorts()
