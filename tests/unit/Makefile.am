AM_CFLAGS = -I$(top_srcdir)/include \
			-I$(top_srcdir)/src \
			-I$(top_srcdir)/tests/utils/ \
			-I$(srcdir) \
			-I$(top_srcdir)/src/lib \
			-DTORSOCKS_FIXTURE_PATH=\"`pwd`/fixtures/\"

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBCOMMON=$(top_builddir)/src/common/libcommon.la

LIBTORSOCKS=$(top_builddir)/src/lib/libtorsocks.la

noinst_PROGRAMS = test_onion test_connection test_utils test_config-file test_socks5 test_compat

EXTRA_DIST = fixtures

test_onion_SOURCES = test_onion.c
test_onion_LDADD = $(LIBTAP) $(LIBCOMMON)

test_connection_SOURCES = test_connection.c
test_connection_LDADD = $(LIBTAP) $(LIBCOMMON)

test_utils_SOURCES = test_utils.c
test_utils_LDADD = $(LIBTAP) $(LIBCOMMON)

test_config_file_SOURCES = test_config-file.c
test_config_file_LDADD = $(LIBTAP) $(LIBCOMMON)

test_socks5_SOURCES = test_socks5.c
test_socks5_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBTORSOCKS)

test_compat_SOURCES = test_compat.c
test_compat_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBTORSOCKS)

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -rf $(srcdir)/$$script $(builddir); \
		done; \
	fi

# Force remove here so make sure EXTRA_DIST does not contain something like
# /usr. ;)
clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -rf $(builddir)/$$script; \
		done; \
	fi
