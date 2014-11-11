AM_CFLAGS = -D_GNU_SOURCE -Wall -Wno-strict-aliasing -I$(top_srcdir)/include/compat -I$(top_srcdir)/include -g -funit-at-a-time -std=gnu99

bin_PROGRAMS = capwap-dp

capwap_dp_SOURCES = capwap-dp.c worker.c netns.c debug.c
capwap_dp_LDADD = @URCU_LIBS@ @URCUCDS_LIBS@

DISTCLEANFILES = *~
