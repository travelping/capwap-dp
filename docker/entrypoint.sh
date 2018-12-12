#!/bin/sh
set -x

"$@" &
pid=$!

if [ -f /etc/capwap-dp/capwap-dp-up.sh ]; then
    sh /etc/capwap-dp/capwap-dp-up.sh
else
    ip link set dev tap0 up
fi

wait $pid
