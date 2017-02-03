CAPWAP Datapath element
=======================
[![Build Status](https://travis-ci.org/travelping/capwap-dp.svg?branch=master)](https://travis-ci.org/travelping/capwap-dp)

BUILDING
--------

Build tools: gcc, automake, autoconf, libtool, shtool

Mandatory build dependencies:

 * [libev](http://software.schmorp.de/pkg/libev.html)
 * [erlang](http://www.erlang.org)
 * [liburcu](http://liburcu.org/)
 * [libconfig](http://www.hyperrealm.com/libconfig/)

Optional build dependencies:

 * [systemd](https://www.freedesktop.org/wiki/Software/systemd/)

On Debian/Ubuntu

    # ./autogen.sh
	# ./configure
	# make
