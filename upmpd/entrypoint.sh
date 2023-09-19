#! /bin/sh
upmpdcli -c /config/upmpdcli.conf -D
mpd --stderr --no-daemon /config/mpd.conf
