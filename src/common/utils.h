/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org>
 *               2008-2011 - Robert Hogan <robert@roberthogan.net>
 *               2013 - David Goulet <dgoulet@ev0ke.net>
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

#ifndef TORSOCKS_UTILS_H
#define TORSOCKS_UTILS_H

#include <netinet/in.h>

#include "compat.h"

char *utils_strsplit(char *separator, char **text, const char *search);
int utils_strcasecmpend(const char *s1, const char *s2);
int utils_tokenize_ignore_comments(const char *_line, size_t size, char **tokens);

int utils_is_address_ipv4(const char *ip);
int utils_is_address_ipv6(const char *ip);
int utils_sockaddr_is_localhost(const struct sockaddr *sa);
int utils_localhost_resolve(const char *name, int af, void *buf, size_t len);
int utils_is_addr_any(const struct sockaddr *sa);
int utils_get_port_from_addr(const struct sockaddr *sa);
const char *utils_get_addr_from_sockaddr(const struct sockaddr *sa);

#endif /* TORSOCKS_UTILS_H */
