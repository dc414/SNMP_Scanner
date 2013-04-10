#! /usr/bin/env python
from scapy.all import *
import argparse
import os
import re
import gevent
from gevent.pool import Group


#  Scans for snmp ports with private.
#  Add scanner for public ports as well?
def scanner(iprange, i):
	f = open(outputfile, 'w+')
	ip = iprange + str(i)
	p = IP(dst=ip)
	UDP(dport=161, sport=39445)
	SNMP(community="private", PDU=SNMPget(id=1416992799, varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]))
	pkt = sr1(p, timeout=1)
	if pkt and pkt.sprintf("%IP.proto%") != "icmp":
		p1 = pkt.sprintf("%SNMP.PDU%").split("ASN1_STRING['", 1)
		p2 = p1[1].split("'", 1)
		if printverbose is True:
			print ip + "\n"
		if justprint is True:
			print pkt.sprintf("%IP.src%") + " - " + p2[0] + "\n"
		else:
			f.write(ip + '  -  ' + pkt.sprintf("%IP.src%") + " - " + p2[0] + "\n")
		if printip is True:
			print pkt.sprintf("%IP.src%") + " - " + p2[0] + "\n"
			f.write(pkt.sprintf("%IP.src%") + " - " + p2[0] + "\n")
	f.close()


# Scan '#' of IP's
def scanwholeip(times):
	scannedips = []
	ipaddress = re.search('(\d+\.\d+\.)(\d+)', iprange)
	octect1and2 = ipaddress.group(0)
	for i in range(1, 255):
		newipaddress = octect1and2 + str(i)
		scannedips[i] = newipaddress
		spawngreenlets(newipaddress)
	return scannedips


# Split scanning into separate processes
def spawngreenlets(iprange):
	threads = []
	group = Group()
	for i in range(1, 255):
		thread[i] = gevent.spawn(scanner(iprange, i, outputfile))
		gevent.sleep(0)
		group.add(thread[i])
	group.join()
	gevent.joinall(threads)


def scan():
	spawngreenlets(ipaddress)
	print "snmpscan is complete."
	if justprint is True:
		if os.stat('/tmp/snmp_output.txt')[6] == 0:
			print "You IP address '" + iprange + "' is secure. Nothing was found under your parameters."
		else:
			print "Something was found! The location of your outputfile is " + outputfile
	if foundips is True:
		print "These are the IP address's you used:\n"
		for i in iplist:
			print ip

# Command-line usage
parser = argparse.ArgumentParser(description='Scan a network for snmp(UDP port 161).')
parser.add_argument(  # IP Address - ipaddress
	'-i',
	'--ip',
	help="Define IP Address of first three octects(example: '127.0.1').",
	required=True,
	nargs='?',
	action='store',
	dest='ipaddress'
)
parser.add_argument(  # Scanmore - times
	'-sm',
	'--scanmore',
	help="Scan more subnets; Amount is required.",
	required=False,
	type=int,
	nargs=1,
	action='store',
	dest='times',
	default='1'
)
parser.add_argument(  # Stop - Boolean return
	'-s',
	'--stop',
	help="Stop scanning after a '#' of node(s) are found.",
	required=False,
	type=int,
	nargs=1,
	action='store',
	dest='stop',
	default='0'
)
parser.add_argument(  # Print - printip
	'-p',
	'--print',
	help="Print node IP's if snmp is 'private'.",
	required=False,
	action='stored_false',
	default=False,
	dest='printip'
)
parser.add_argument(  # Just print - justprint
	'-jp',
	'--justprint',
	help="Don't save found IP's to file, just print in console",
	required=False,
	action='stored_false',
	default=False,
	dest='justprint'
)
parser.add_argument(  # Verbose - printverbose
	'-v',
	'-verbose',
	help="Used with '-p', more verbose info.",
	required=False,
	action='stored_false',
	default=False,
	dest='printverbose'
)
parser.add_argument(  # Output File - outputfile
	'-of',
	'--outputfile',
	help="Define output file, default location is '/tmp/snmp_output.txt'",
	required=False,
	default='/tmp/snmp_output.txt',
	type=str,
	nargs='?',
	action='store',
	dest='outputfile'
)

args = vars(parser.parse_args())
