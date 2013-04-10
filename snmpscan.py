#! /usr/bin/env python
from scapy.all import *
import argparse
import os
import re  # http://www.secdev.org/projects/scapy/doc/advanced_usage.html#a-complete-example-snmp


iprange = raw_input('\nEnter IP Range, without last octet.\n Example: "127.0.1"\n IP Range:  ') + '.'


def scanner():
	f = open('/tmp/snmp_output.txt', 'w+')
	for i in range(1, 255):
		ip = iprange + str(i)
		print ip + "\n"
		p = IP(dst=ip)
		UDP(dport=161, sport=39445)
		SNMP(community="private", PDU=SNMPget(id=1416992799, varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]))
		pkt = sr1(p, timeout=1)
		if pkt and pkt.sprintf("%IP.proto%") != "icmp":
			p1 = pkt.sprintf("%SNMP.PDU%").split("ASN1_STRING['", 1)
			p2 = p1[1].split("'", 1)
			print pkt.sprintf("%IP.src%") + " - " + p2[0]
			f.write(pkt.sprintf("%IP.src%") + " - " + p2[0] + "\n")
	f.close()
	print "\nDone!\n"


def scanwhole():
	if os.stat('/tmp/snmp_output.txt')[6] == 0:
		answer = raw_input('\nIf no nothing is found in first IP Range, should I scan the next subnet?  ')
		if answer in ('y', 'Y'):
			m = re.search('(\d+\.\d+\.)(\d+)', iprange)
			first_and_second_octects = m.group(0)
			third_octect = m.group(1)
			for i in range(1, 255):
				first_and_second_octects += str(i)
				for i in range(1, 255):
					third_octect += str(i)
					scanner()
		else:
			scanner()

scanwhole()

parser = argparse.ArgumentParser(description='')
