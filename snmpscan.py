#!/usr/bin/env python
from scapy.all import *
import argparse
import os
from subprocess import call
from netaddr import *

def scanner(ipaddr, community):
	if(call(['./snmpscan.sh', '-c', community, str(ipaddr)]) == 0):
		print "worked"

parser = argparse.ArgumentParser(description='Scan a network for snmp(UDP port 161).')
parser.add_argument("subnet", help="Network in subnet notation (example: 127.0.0.0/24)")
parser.add_argument("-s", "--stop", help="Stop scanning after a '#' of node(s) are found.",	type=int)
parser.add_argument("-c", "--community", help="SNMP community string, 'private' default", default="private")
parser.add_argument("-t", "--threads", help="threads", default=20)
parser.add_argument("-v", "--verbose", help="verbose", required=False, action="store_true")
args = parser.parse_args()

for ip in IPNetwork(args.subnet):
	print "Trying " + str(ip) + "... "
	scanner(ip, args.community)
