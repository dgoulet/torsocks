AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(builddir)
#AM_CFLAGS = -fno-strict-aliasing

libdir = @libdir@/torsocks

# Install invocation scripts
#bin_SCRIPTS = torsocks usewithtor
#INSTALL_SCRIPT = $(install_sh) -c -m 755
EXTRA_DIST = torsocks.in usewithtor.in

lib_LTLIBRARIES = libtorsocks.la

libtorsocks_la_SOURCES = torsocks.c torsocks.h

libtorsocks_la_LIBADD = \
		$(top_builddir)/src/common/libcommon.la \
		-ldl
