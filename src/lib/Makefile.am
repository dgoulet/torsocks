AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(builddir)
#AM_CFLAGS = -fno-strict-aliasing

libdir = @libdir@/torsocks

# Install invocation scripts
lib_LTLIBRARIES = libtorsocks.la

libtorsocks_la_SOURCES = torsocks.c torsocks.h \
                         connect.c gethostbyname.c getaddrinfo.c close.c \
                         getpeername.c socket.c syscall.c socketpair.c recv.c \
                         exit.c accept.c listen.c fclose.c

libtorsocks_la_LIBADD = $(top_builddir)/src/common/libcommon.la
