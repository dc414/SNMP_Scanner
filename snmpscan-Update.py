#! /usr/bin/env python
from scapy.all import *  # Scapy Usage
import argparse  # Use snmpscan.py straight from cmdline
import os  # Open system files
import re  # Regular Expressions
import gevent  # Spawn Greenlets
from gevent.pool import Group  # Greenlet grouping


#  Scans for snmp ports with private.
#  Add scanner for public ports as well?
def scanner(iprange, i, outputfile):
	f = open(outputfile, 'w+')
	ip = iprange + str(i)
	print ip + "\n"
	p = IP(dst=ip)
	UDP(dport=161, sport=39445)
	SNMP(community="private", PDU=SNMPget(id=1416992799, varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]))
	pkt = sr1(p, timeout=1)
	if pkt and pkt.sprintf("%IP.proto%") != "icmp":
		p1 = pkt.sprintf("%SNMP.PDU%").split("ASN1_STRING['", 1)
		p2 = p1[1].split("'", 1)
		f.write(pkt.sprintf("%IP.src%") + " - " + p2[0] + "\n")
	f.close()
	if os.stat('/tmp/snmp_output.txt')[6] == 0:
		print "\nI'm sorry nothing was found."
	else:
		return


def scanwhole(times):
	ipaddress = re.search('(\d+\.\d+\.)(\d+)', iprange)
	octect1and2 = ipaddress.group(0)
	for i in range(1, 255):
		octect1and2 + str(i)
		scanner()


# Split scanning into 5 separate processes
def spawngreenlets(iprange, outputfile):
	threads = []
	group = Group()
	for i in range(1, 255):
		thread[i] = gevent.spawn(scanner(iprange, i, outputfile))
		gevent.sleep(0)
		group.add(thread[i])
	group.join()
	gevent.joinall(threads)


# Command-line usage
parser = argparse.ArgumentParser(description='Scan a network for snmp.')
parser.add_argument('-i', '--ip', help="Define IP Address(example: '127.0.1')", required=True, nargs='?')
parser.add_argument('-sm', '--scanmore', help="Scan more subnets; Amount is required.", required=False, type=int, nargs=1)
parser.add_argument('-s', '--stop', help="Stop scanning after a '#' of node(s) are found", required=False, type=int, nargs=1)
parser.add_argument('-p', '--print', help="Print node IP's if snmp is 'private'", required=False)
parser.add_argument('-v', '-verbose', help="Used with '-p', more verbose info.", required=False)
parser.add_argument('-of', '--outputfile', help="Define output file, default location is '/tmp/snmp_output.txt'", required=False, default='/tmp/snmp_output.txt', type=str, nargs='?')
args = vars(parser.parse_args())

if args in ('-i', '--ip'):
	spawngreenlets()

if args in ('-p'):
	printip = True
else:
	printip = False
