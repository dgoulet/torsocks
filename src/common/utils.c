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
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "macros.h"
#include "utils.h"

/*
 * Return 1 if the given IP belongs in the af domain else return a negative
 * value.
 */
static int check_addr(const char *ip, int af)
{
	int ret = 0;
	char buf[128];

	assert(ip);

	ret = inet_pton(af, ip, buf);
	if (ret != 1) {
		ret = -1;
	}

	return ret;
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
 * This routines breaks up input lines into tokens and places these tokens into
 * the array specified by tokens
 *
 * Return the number of token plus one set in the given array.
 */
ATTR_HIDDEN
int utils_tokenize_ignore_comments(const char *_line, size_t size, char **tokens)
{
	int ret, i = 0, argc = 0;
	char *c, *line = NULL;

	assert(_line);
	assert(tokens);

	line = strdup(_line);

	/* Ignore line if it starts with a # meaning a comment. */
	if (*line == '#') {
		goto end;
	}

	/* Count number of token. If larger than size, we return an error. */
	c = line;
	while ((c = strchr(c + 1, ' '))) {
		/* Skip consecutive spaces. */
		if (*(c + 1) == ' ') {
			continue;
		}
		argc++;
	}

	if (argc > size) {
		ret = -ENOMEM;
		goto error;
	}

	c = strtok(line, " \t");
	while (c != NULL) {
		tokens[i] = strdup(c);
		c = strtok(NULL, " \t");
		i++;
	}

end:
	ret = i;
error:
	free(line);
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
 * Check if the given IPv4 is in the loopback net (127.x.x.x).
 *
 * Return 1 if so else 0 if not.
 */
ATTR_HIDDEN
int utils_is_ipv4_local(in_addr_t addr)
{
	assert(addr);

	return IN_LOOPBACK(addr);
}
