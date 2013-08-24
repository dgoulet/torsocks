SUBDIRS = utils

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBTORSOCKS=$(top_builddir)/src/lib/libtorsocks.la

noinst_PROGRAMS = test_dns

test_dns_SOURCES = test_dns.c
test_dns_LDADD = $(LIBTAP) $(LIBTORSOCKS)

check-am:
	./run.sh test_list

dist_noinst_SCRIPTS = test_list run.sh
EXTRA_DIST = run.sh test_list
