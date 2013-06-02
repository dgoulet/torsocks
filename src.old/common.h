/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2000-2008 Shaun Clowes <delius@progsoc.org>             *
 *   Copyright (C) 2008-2011 Robert Hogan <robert@roberthogan.net>         *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

/* Common functions provided in common.c */
/* GCC has several useful attributes. */
#include <sys/types.h>

#if defined(__GNUC__) && __GNUC__ >= 3
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_PURE __attribute__((pure))
#define ATTR_CONST __attribute__((const))
#define ATTR_MALLOC __attribute__((malloc))
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_NONNULL(x) __attribute__((nonnull x))
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be true. */
#define PREDICT_LIKELY(exp) __builtin_expect((exp), 1)
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be false. */
#define PREDICT_UNLIKELY(exp) __builtin_expect((exp), 0)
#else
#define ATTR_NORETURN
#define ATTR_PURE
#define ATTR_CONST
#define ATTR_MALLOC
#define ATTR_NORETURN
#define ATTR_NONNULL(x)
#define PREDICT_LIKELY(exp) (exp)
#define PREDICT_UNLIKELY(exp) (exp)
#endif

/** Try to find the symbol that is either m or __m.
 * If one of them exists, in that order, then save its address in r,
 * otherwise we want to print a message at log level l stating that
 * we could not find it.
 */
#define torsocks_find_library(m,l,r) \
  do { \
    char * dl_error_msg = ""; \
    char * dl_error_msg2 = ""; \
    dlerror(); \
    if ((r = dlsym(RTLD_NEXT, m)) == NULL) { \
      dl_error_msg = dlerror(); \
      if (dl_error_msg != NULL) { \
        dl_error_msg = strdup(dl_error_msg); \
      } \
      if ((r = dlsym(RTLD_NEXT, "__" m)) == NULL) { \
        dl_error_msg2 = dlerror(); \
        show_msg(l, "WARNING: The symbol %s() was not found in any shared " \
          "library with the reported error: %s!\n" \
          "  Also, we failed to find the symbol %s() with the reported error:" \
          " %s\n", m, (dl_error_msg ? dl_error_msg : "Not Found"), \
          "__"m, (dl_error_msg2 ? dl_error_msg2 : "Not Found")); \
      } \
      if (dl_error_msg) \
        free(dl_error_msg); \
    } \
  } while (0)

uint16_t get_uint16(const char *cp) ATTR_PURE ATTR_NONNULL((1));
uint32_t get_uint32(const char *cp) ATTR_PURE ATTR_NONNULL((1));
void set_uint16(char *cp, uint16_t v) ATTR_NONNULL((1));
void set_uint32(char *cp, uint32_t v) ATTR_NONNULL((1));

int is_internal_IP(uint32_t ip, int for_listening) ATTR_PURE;
int parse_addr_port(int severity, const char *addrport, char **address,
                    uint32_t *addr, uint16_t *port_out);

void set_log_options(int, char *, int);
void show_msg(int level, const char *, ...);
int count_netmask_bits(uint32_t mask);
unsigned int resolve_ip(char *, int, int);

#define MSGNONE   -1
#define MSGERR    0
#define MSGWARN   1
#define MSGTEST  2
#define MSGNOTICE 3
#define MSGDEBUG  3

/* Required by some BSDs */
#ifndef  MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif
