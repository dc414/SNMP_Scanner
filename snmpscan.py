#! /usr/bin/env python
from scapy.all import *
import argparse
import re
import gevent
from netaddr import IPNetwork


#  Scans for snmp ports with private.
#  Add scanner for public ports as well?
def scanner(ipaddr):
	p = IP(dst=ipaddr)
	UDP(dport=161, sport=39445)
	SNMP(community="private", PDU=SNMPget(id=1416992799, varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]))
	pkt = sr1(p, timeout=1)
	if pkt and pkt.sprintf("%IP.proto%") != "icmp":
		p1 = pkt.sprintf("%SNMP.PDU%").split("ASN1_STRING['", 1)
		p2 = p1[1].split("'", 1)
		subnetnotsecure[p] = pkt.sprintf("%IP.src%") + " - " + p2[0] + "\n"
	else:
		print subnetsecure[p]


# Which IP's to scan.
def whattoscan(Subnet):
	print Subnet
	threads = []
	iplist = []
	subnetlist = list(IPNetwork(Subnet))
	for found in subnetlist:
		iplist[found] = re.search('(\.re{9}\.\.)(\d+\.\d+\.\d+\.\d+)(\.\.)', subnetlist)
		print iplist[found]
	for ip in list(IP):
		threads[i] = gevent.spawn(scanner(ip))
		gevent.sleep(0)
	gevent.joinall(threads)


def scan():
	whattoscan(Subnet)
	print "snmpscan is complete."
	print "Your subnet '" + Subnet + "' is secure. Nothing was found under your parameters."

# Command-line usage
parser = argparse.ArgumentParser(description='Scan a network for snmp(UDP port 161).')
parser.add_argument(
	"Subnet",
	type=str,
	nargs='?',
	help="Network in subnet notation (example: 127.0.0.0/24)",
	action='store'
)
parser.add_argument(  # Stop - Boolean return
	'-s',
	help="Stop scanning after a '#' of node(s) are found.",
	required=False,
	type=int,
	nargs=1,
	action='store',
	dest='stop',
	default=0
)
parser.add_argument(  # Verbose - printverbose
	'-v',
	help="Used with '-p', more verbose info.",
	required=False,
	action='store_false',
	default=False,
	dest='printverbose'
)

args = vars(parser.parse_args())
Subnet = args['Subnet']
scan()
