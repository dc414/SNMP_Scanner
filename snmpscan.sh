#!/bin/bash

verbose=0
community=private

show_help() {
	echo "usage: snmpscan.sh [OPTIONS] host

	 Scan a host that respond to your community string

	   subnet        Network in subnet notation (example: 127.0.0.0/24)

	   options:
		   -h, --help  show this help message and exit
		   -c public   community string
		   -v          verbose"
}

realargs="$@"
while [ $# -gt 0 ]; do
	case "$1" in
		-h)
			show_help
			exit 255
			;;
		-c)
			community=$2
			;;
		*)
			host=$2
			break 2
			;;
	esac
	shift
done
set -- $realargs

if snmpget -v2c -c $community -t 1 $host:161 1.3.6.1.2.1.1.1.0 2>&1 >/dev/null; then
	exit 0
else
	exit 1
fi
