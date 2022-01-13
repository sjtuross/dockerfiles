#!/bin/sh
if [ ! -f /smartdns/smartdns.conf ]; then
	cp -u /etc/smartdns.conf /smartdns/smartdns.conf
fi
exec /bin/smartdns -f -x -c /smartdns/smartdns.conf
