#!/bin/sh -e

rm -rf autom4te.cache config
rm -f configure config.h.in

mkdir -p config

libtoolize -f -c
autoreconf --install --symlink --force
