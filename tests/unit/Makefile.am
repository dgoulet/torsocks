AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBCOMMON=$(top_builddir)/src/common/libcommon.la

noinst_PROGRAMS = test_onion test_connection test_utils

test_onion_SOURCES = test_onion.c
test_onion_LDADD = $(LIBTAP) $(LIBCOMMON)

test_connection_SOURCES = test_connection.c
test_connection_LDADD = $(LIBTAP) $(LIBCOMMON)

test_utils_SOURCES = test_utils.c
test_utils_LDADD = $(LIBTAP) $(LIBCOMMON)
