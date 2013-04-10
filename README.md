SNMP Scanner
============

##Requirements:
1. scapy
```
sudo apt-get install python-scapy
```
2. libevent (requirement for gevent)
```
sudo apt-get install libevent-dev
```
3. gevent
```
sudo apt-get install gevent
```
4. netaddr
```
sudo apt-get install python-netaddr
```

##Usage:
Needs root to run!
```
usage: snmpscan.py [-h] [-s STOP] [-v] subnet

Scan a network for snmp(UDP port 161).

positional arguments:
  subnet      Network in subnet notation (example: 127.0.0.0/24)

optional arguments:
  -h, --help  show this help message and exit
  -s STOP     Stop scanning after a '#' of node(s) are found.
  -v          Used with '-p', more verbose info.

```

snmp scan a network!
