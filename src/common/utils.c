/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org>
 * 				 2008-2011 - Robert Hogan <robert@roberthogan.net>
 * 				 	  2013 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "macros.h"
#include "utils.h"

/*
 * Hardcoded list of localhost hostname. In order to resolve these for an
 * application, usually we would need to check in /etc/hosts by using
 * gethostent() but in order to avoid DNS resolution outside of Tor (even local
 * file), only the localhost is resolved and the rest is sent through Tor.
 */
static const char *localhost_names_v4[] = {
	"localhost", "ip-localhost", NULL,
};

static const char *localhost_names_v6[] = {
	"localhost", "ip6-loopback", "ip6-localhost", NULL,
};

/*
 * Return 1 if the given IP belongs in the af domain else return 0 if the
 * given ip is not a valid address or the af value is unknown.
 */
static int check_addr(const char *ip, int af)
{
	int ret = 0;
	char buf[128];

	assert(ip);

	ret = inet_pton(af, ip, buf);
  if (ret == -1) {
    /* Possible if the af value is unknown to inet_pton. */
    ret = 0;
  }

	return ret;
}

/*
 * Given a name string and a list NULL terminated of strings, this will try to
 * match the name.
 *
 * Return the entry in the list if match else NULL.
 */
static const char *match_name(const char *name, const char **list)
{
	unsigned int count = 0;
	const char *entry;

	assert(name);
	assert(list);

	while ((entry = list[count]) != NULL) {
		int ret;

		ret = strcmp(entry, name);
		if (!ret) {
			/* Match. */
			goto end;
		}
		count++;
	}

end:
	return entry;
}

/*
 * Return 1 if the given IP is an IPv4.
 */
ATTR_HIDDEN
int utils_is_address_ipv4(const char *ip)
{
	return check_addr(ip, AF_INET);
}

/*
 * Return 1 if the given IP is an IPv6.
 */
ATTR_HIDDEN
int utils_is_address_ipv6(const char *ip)
{
	return check_addr(ip, AF_INET6);
}

/*
 * This routine breaks up input lines into tokens and places these tokens into
 * the array specified by tokens.
 *
 * Return the number of tokens plus one set in the given array.
 */
ATTR_HIDDEN
int utils_tokenize_ignore_comments(const char *_line, size_t size, char **tokens)
{
	int ret, i = 0;
	char *c, *line = NULL, *saveptr;

	assert(_line);
	assert(tokens);
	assert(size <= INT_MAX);

	line = strdup(_line);
	if (!line) {
		ret = -ENOMEM;
		goto error;
	}

	/* Ignore line if it starts with a # meaning a comment. */
	if (*line == '#') {
		goto end;
	}

	c = strtok_r(line, " \t", &saveptr);
	while (c != NULL) {
		if ((size_t) i >= size) {
			ret = -ENOMEM;
			goto error;
		}
		tokens[i] = strdup(c);
		if (!tokens[i]) {
			ret = -ENOMEM;
			goto error;
		}
		c = strtok_r(NULL, " \t", &saveptr);
		i++;
	}

end:
	ret = i;
	free(line);
	return ret;

error:
	free(line);
	while (i-- > 0) {
		free(tokens[i]);
	}
	return ret;
}

/*
 * This function is very much like strsep, it looks in a string for a character
 * from a list of characters, when it finds one it replaces it with a \0 and
 * returns the start of the string (basically spitting out tokens with
 * arbitrary separators).
 *
 * If no match is found the remainder of the string is returned and the start
 * pointer is set to be NULL. The difference between standard strsep and this
 * function is that this one will set separator to the character separator
 * found if it isn't NULL.
 */
ATTR_HIDDEN
char *utils_strsplit(char *separator, char **text, const char *search)
{
	unsigned int len;
	char *ret;

	ret = *text;

	if (*text == NULL) {
		if (separator) {
			*separator = '\0';
		}
		return NULL;
	}

	len = strcspn(*text, search);
	if (len == strlen(*text)) {
		if (separator) {
			*separator = '\0';
		}
		*text = NULL;
	} else {
		*text = *text + len;
		if (separator) {
			*separator = **text;
		}
		**text = '\0';
		*text = *text + 1;
	}

	return ret;
}

/*
 * Compares the last strlen(s2) characters of s1 with s2.
 *
 * Returns as for strcasecmp.
 */
ATTR_HIDDEN
int utils_strcasecmpend(const char *s1, const char *s2)
{
	size_t n1 = strlen(s1), n2 = strlen(s2);

	if (n2 > n1) {
		/* Then they can't be the same; figure out which is bigger */
		return strcasecmp(s1, s2);
	} else {
		return strncasecmp(s1 + (n1 - n2), s2, n2);
	}
}

/*
 * Return 1 if the given sockaddr is localhost else 0
 */
ATTR_HIDDEN
int utils_sockaddr_is_localhost(const struct sockaddr *sa)
{
	int is_localhost;

	assert(sa);

	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
		is_localhost = ((ntohl(sin->sin_addr.s_addr) & TSOCKS_CLASSA_NET) ==
				TSOCKS_LOOPBACK_NET);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;
		static const uint8_t addr[] = TSOCKS_LOOPBACK6;
		is_localhost = !memcmp(sin6->sin6_addr.s6_addr, addr,
				sizeof(sin6->sin6_addr.s6_addr));
	} else {
		/* Unknown sockaddr family thus not localhost. */
		is_localhost = 0;
	}

	return is_localhost;
}

/*
 * Try to match a given name to localhost names (v4 and v6).
 *
 * If a match is found, the address in network byte order is copied in the
 * buffer thus len must match the size of the given address family and 1 is
 * returned.
 *
 * If NO match is found, 0 is return and buf is untouched.
 *
 * If len is the wrong size, -EINVAL is returned and buf is untouched.
 */
ATTR_HIDDEN
int utils_localhost_resolve(const char *name, int af, void *buf, size_t len)
{
	const char *entry;

	assert(name);
	assert(buf);

	if (af == AF_INET) {
		const in_addr_t addr = htonl(TSOCKS_LOOPBACK);

		entry = match_name(name, localhost_names_v4);
		if (entry) {
			if (len < sizeof(in_addr_t)) {
				/* Size of buffer is not large enough. */
				goto error;
			}
			memcpy(buf, &addr, sizeof(addr));
			goto match;
		}
	} else if (af == AF_INET6) {
		const uint8_t addr[] = TSOCKS_LOOPBACK6;

		entry = match_name(name, localhost_names_v6);
		if (entry) {
			if (len < sizeof(addr)) {
				/* Size of buffer is not large enough. */
				goto error;
			}
			memcpy(buf, addr, sizeof(addr));
			goto match;
		}
	} else {
		/* Unknown family type. */
		assert(0);
		goto error;
	}

	/* No match. */
	return 0;
match:
	/* Match found. */
	return 1;
error:
	return -EINVAL;
}

/*
 * For a given sockaddr, check if the IP address is ANY which is 0.0.0.0 for
 * IPv4 and :: for IPv6.
 *
 * Return 1 if it is else 0.
 */
ATTR_HIDDEN
int utils_is_addr_any(const struct sockaddr *sa)
{
	int ret;

	assert(sa);

	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
		ret = (sin->sin_addr.s_addr == TSOCKS_ANY);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;
		const uint8_t addr[] = TSOCKS_ANY6;
		ret = !memcmp(sin6->sin6_addr.s6_addr, addr,
				sizeof(sin6->sin6_addr.s6_addr));
	} else {
		ret = 0;
		goto end;
	}

end:
	return ret;
}

/*
 * For a given sockaddr, return the port value considering the address family
 * structure.
 *
 * Return the port number in the sockaddr sa or -1 is family is not unknown.
 */
ATTR_HIDDEN
int utils_get_port_from_addr(const struct sockaddr *sa)
{
	int port;

	assert(sa);

	if (sa->sa_family == AF_INET) {
		port = ((const struct sockaddr_in *) sa)->sin_port;
	} else if (sa->sa_family == AF_INET6) {
		port = ((const struct sockaddr_in6 *) sa)->sin6_port;
	} else {
		port = -1;
	}

	return port;
}

/*
 * For a given sockaddr, return a const pointer to the address data structure.
 * Return NULL if family is not IPv4 or IPv6.
 */
ATTR_HIDDEN
const char *utils_get_addr_from_sockaddr(const struct sockaddr *sa)
{
  static char buf[256];
  const void *addrp;

  assert(sa);

  memset(buf, 0, sizeof(buf));

  if (sa->sa_family == AF_INET) {
    addrp = &((const struct sockaddr_in *) sa)->sin_addr;
  } else if (sa->sa_family == AF_INET6) {
    addrp = &((const struct sockaddr_in6 *) sa)->sin6_addr;
  } else {
    goto end;
  }

  inet_ntop(sa->sa_family, addrp, buf, sizeof(buf));

end:
  return buf;
}
