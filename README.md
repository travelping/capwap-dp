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

Docker container images
------------------------

This repository also creates a [Docker
image](https://hub.docker.com/r/ergw/capwap-dp/) which can be used as a
base for other images to create a CAPWAP AC data path.  At the time of writing we
recommend to use this base image for testing and development. You can use the
host network and need network interfaces to be configured beforehand.

To add a custom configuration to the container, a volume may be mounted
to `/etc/capwap-dp.conf`.

Running
-------

For running under unprivileged user should add capabilities:

	# sudo setcap CAP_NET_ADMIN,CAP_IPC_LOCK,CAP_SYS_NICE=+eip src/capwap-dp
