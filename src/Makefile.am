AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
AM_CFLAGS = -D_GNU_SOURCE -Wall -Wno-strict-aliasing -g -funit-at-a-time -std=gnu99 \
	    $(SYSTEMD_DAEMON_CFLAGS) \
	    -I$(top_srcdir)/include/compat \
	    -I$(top_srcdir)/include
AM_LDFLAGS = $(SYSTEMD_DAEMON_LIBS)

bin_PROGRAMS = capwap-dp
sysconf_DATA = capwap-dp.conf

capwap_dp_SOURCES = capwap-dp.c worker.c netns.c debug.c
capwap_dp_LDADD = @URCU_LIBS@ @URCUCDS_LIBS@ @LIBCONFIG_LIBS@

DISTCLEANFILES = *~
