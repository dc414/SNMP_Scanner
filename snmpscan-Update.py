#! /usr/bin/env python
from scapy.all import *
import argparse
import os
import re
import gevent
import netaddr
from gevent.pool import Group


#  Scans for snmp ports with private.
#  Add scanner for public ports as well?
def scanner(ipaddr):
	p = IP(dst=ipaddr)
	UDP(dport=161, sport=39445)
	SNMP(community="private", PDU=SNMPget(id=1416992799, varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]))

	print >> sys.stderr, "Trying " + ip + " ... "
	pkt = sr1(p, timeout=1)
	if pkt and pkt.sprintf("%IP.proto%") != "icmp":	
		print >> sys.stderr, "OK\n"
		p1 = pkt.sprintf("%SNMP.PDU%").split("ASN1_STRING['", 1)
		p2 = p1[1].split("'", 1)
		
		print pkt.sprintf("%IP.src%") + " - " + p2[0] + "\n"
	else:
		print >> sys.stderr, "No reply\n"

# Scan '#' of IP's
def scanwholeip(times):
	scannedips = []
	ipaddress = re.search('(\d+\.\d+\.)(\d+)', subnet)
	octect1and2 = ipaddress.group(0)
	for i in range(1, 255):
		newipaddress = octect1and2 + str(i)
		scannedips[i] = newipaddress
		spawngreenlets(newipaddress)
	return scannedips


# Split scanning into separate processes
def spawngreenlets(subnet):
	threads = []
	group = Group()
	for ip in IPNetwork(subnet):
		thread[i] = gevent.spawn(scanner(ip, outputfile))
		gevent.sleep(0)
		group.add(thread[i])
	group.join()
	gevent.joinall(threads)


def scan():
	spawngreenlets(ipaddress)
	print "snmpscan is complete."
	if justprint is True:
		if os.stat('/tmp/snmp_output.txt')[6] == 0:
			print "Your subnet '" + subnet + "' is secure. Nothing was found under your parameters."
		else:
			print "Something was found! The location of your outputfile is " + outputfile
	if foundips is True:
		print "These are the IP address's you used:\n"
		for i in iplist:
			print ip

# Command-line usage
parser = argparse.ArgumentParser(description='Scan a network for snmp(UDP port 161).')
parser.add_argument(  # Stop - Boolean return
	'-s',
	'--stop',
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
	'-verbose',
	help="Used with '-p', more verbose info.",
	required=False,
	action='store_false',
	default=False,
	dest='printverbose'
)

args = vars(parser.parse_args())
