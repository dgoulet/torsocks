# Makefile used by configure to create real Makefile

libdir = @libdir@/torsocks

# Install invocation scripts
bin_SCRIPTS = torsocks usewithtor
INSTALL_SCRIPT = $(install_sh) -c -m 755

libtorsocks_la_LDFLAGS= $(TORSOCKSLDFLAGS)
# Install main library to $(prefix)/lib/tor (must match torsocks.in)
lib_LTLIBRARIES = libtorsocks.la
libtorsocks_la_SOURCES = torsocks.c common.c parser.c dead_pool.c darwin_warts.c socks.c\
				common.h  dead_pool.h  expansion_table.h  parser.h  socks.h

DISTCLEANFILES=parser.lo dead_pool.lo common.lo libtorsocks.lo torsocks.lo darwin_warts.lo socks.lo\
			   config.cache config.log config.h Makefile \
			   aclocal.m4 config.status usewithtor torsocks \
			   autom4te.cache .libs .deps 
