#!/usr/bin/env python
from scapy.all import *
import argparse
import os
from netaddr import *
import pprint

#  Scans for snmp ports with private.
#  Add scanner for public ports as well?
def scanner(ipaddr, community):
	p = IP(dst=str(ipaddr))
	UDP(dport=161, sport=39445)
	SNMP(community=community, PDU=SNMPget(id=1416992799, varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]))
	pkt = sr1(p, timeout=1, verbose=0)
	if pkt:
		print "host is UP"
		if ICMP in pkt:
			return False

		print pkt.show()
		oid = pkt[SNMPvarbind].oid.val
		val = pkt[SNMPvarbind].value.val
		print "oid: " + str(oid)
		print "val: " + str(val)

parser = argparse.ArgumentParser(description='Scan a network for snmp(UDP port 161).')
parser.add_argument("subnet", help="Network in subnet notation (example: 127.0.0.0/24)")
parser.add_argument("-s", "--stop", help="Stop scanning after a '#' of node(s) are found.",	type=int)
parser.add_argument("-c", "--community", help="SNMP community string, 'private' default", default="private")
parser.add_argument("-t", "--threads", help="threads", default=20)
parser.add_argument("-v", "--verbose", help="verbose", required=False, action="store_true")
args = parser.parse_args()

for ip in IPNetwork(args.subnet):
	print "Trying " + str(ip) + "... "
	if scanner(ip, args.community):
		print "OK\n"
	else:
		print "No SNMP reply\n"
