#! /usr/bin/env python
from scapy.all import *
import argparse
import gevent
from netaddr import *


#  Scans for snmp ports with private.
#  Add scanner for public ports as well?
def scanner(ipaddr, community):
	notsecure = {}
	print str(ipaddr) + '\n'
	p = IP(dst=str(ipaddr))
	UDP(dport=161, sport=39445)
	SNMP(community=args.community, PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]))
	pkt = sr1(p, timeout=1)
	gevent.sleep(1)
	if pkt and pkt.sprintf("%IP.proto%") != "icmp":
		p1 = pkt.sprintf("%SNMP.PDU%").split("ASN1_STRING['", 1)
		p2 = p1[1].split("'", 1)
		notsecure[p] = pkt.sprintfls("%IP.src%") + " %s\n" % (p2[0], )
	print '\n\n'
	print notsecure


# Which IP's to scan.
def nowscanning():
	threads = [gevent.spawn(scanner, ip, args.community) for ip in IPNetwork(args.subnet)]
	gevent.joinall(threads)


def scan():
	nowscanning()
	print "snmpscan is complete."

parser = argparse.ArgumentParser(description='Scan a network for snmp(UDP port 161).')
parser.add_argument("subnet", help="Network in subnet notation (example: 127.0.0.0/24)")
parser.add_argument("-s", "--stop", help="Stop scanning after a '#' of node(s) are found.",	type=int)
parser.add_argument("-c", "--community", help="SNMP community string, 'private' default", default="private")
parser.add_argument("-t", "--threads", help="threads", default=20)
parser.add_argument("-v", "--verbose", help="verbose", required=False, action="store_true")
args = parser.parse_args()

scan()
