AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
AM_CFLAGS = -D_GNU_SOURCE -Wall -Wno-strict-aliasing -g -funit-at-a-time -std=gnu99 \
	    $(SYSTEMD_DAEMON_CFLAGS) $(SYSTEMD_JOURNAL_CFLAGS) \
	    -I$(top_srcdir)/include/compat \
	    -I$(top_srcdir)/include

bin_PROGRAMS = capwap-dp
sysconf_DATA = capwap-dp.conf

capwap_dp_SOURCES = capwap-dp.c worker.c netns.c log.c
capwap_dp_LDADD = $(URCU_LIBS) $(URCUCDS_LIBS) $(LIBCONFIG_LIBS) $(SYSTEMD_DAEMON_LIBS) $(SYSTEMD_JOURNAL_LIBS)

DISTCLEANFILES = *~
