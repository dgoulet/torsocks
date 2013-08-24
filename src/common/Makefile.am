AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

AM_CFLAGS = -fno-strict-aliasing

noinst_LTLIBRARIES = libcommon.la
libcommon_la_SOURCES = log.c log.h config-file.c config-file.h utils.c utils.h \
                       compat.c compat.h socks5.c socks5.h defaults.h macros.h \
                       connection.c connection.h ht.h ref.h onion.c onion.h
