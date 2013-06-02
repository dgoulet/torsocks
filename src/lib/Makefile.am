AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(builddir)

libdir = @libdir@/torsocks

# Install invocation scripts
bin_SCRIPTS = torsocks usewithtor
INSTALL_SCRIPT = $(install_sh) -c -m 755

lib_LTLIBRARIES = libtorsocks.la

libtorsocks_la_SOURCES =

libtorsocks_la_LDFLAGS = $(TORSOCKSLDFLAGS)

libtorsocks_la_LIBADD = \
		$(top_builddir)/src/common/libcommon.la
