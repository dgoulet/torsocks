SUBDIRS = utils unit

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBTORSOCKS=$(top_builddir)/src/lib/libtorsocks.la

noinst_PROGRAMS = test_dns test_socket test_connect test_fd_passing test_getpeername

test_dns_SOURCES = test_dns.c
test_dns_LDADD = $(LIBTAP) $(LIBTORSOCKS)

test_socket_SOURCES = test_socket.c
test_socket_LDADD = $(LIBTAP) $(LIBTORSOCKS)

test_connect_SOURCES = test_connect.c
test_connect_LDADD = $(LIBTAP) $(LIBTORSOCKS)

test_fd_passing_SOURCES = test_fd_passing.c
test_fd_passing_LDADD = $(LIBTAP) $(LIBTORSOCKS) -lpthread

test_getpeername_SOURCES = test_getpeername.c
test_getpeername_LDADD = $(LIBTAP) $(LIBTORSOCKS)

check-am:
	./run.sh test_list

dist_noinst_SCRIPTS = test_list run.sh
EXTRA_DIST = run.sh test_list
