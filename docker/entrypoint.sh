#!/bin/sh
set -e

"$@" &
pid=$!

if [ -f /etc/capwap-dp/capwap-dp-up.sh ]; then
    /etc/capwap-dp/capwap-dp-up.sh
else
    ip link set dev tap0 up
fi

wait $pid
