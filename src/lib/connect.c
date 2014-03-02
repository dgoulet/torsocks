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

#include <assert.h>

#include <common/connection.h>
#include <common/log.h>
#include <common/onion.h>
#include <common/utils.h>

#include "torsocks.h"

/* connect(2) */
TSOCKS_LIBC_DECL(connect, LIBC_CONNECT_RET_TYPE, LIBC_CONNECT_SIG)

/*
 * Torsocks call for connect(2).
 */
LIBC_CONNECT_RET_TYPE tsocks_connect(LIBC_CONNECT_SIG)
{
	int ret, sock_type;
	socklen_t optlen;
	struct connection *new_conn;
	struct onion_entry *on_entry;

	DBG("Connect catched on fd %d", sockfd);

	optlen = sizeof(sock_type);
	ret = getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen);
	if (ret < 0) {
		/* Use the getsockopt() errno value. */
		goto error;
	}

	/* We can't handle a non inet socket. */
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
		DBG("[conect] Connection is not IPv4/v6. Ignoring.");
		goto libc_connect;
	}

	/*
	 * Refuse non stream socket. There is a chance that this might be a DNS
	 * request that we can't pass through Tor using raw UDP packet.
	 */
	if (sock_type != SOCK_STREAM) {
		WARN("[connect] UDP or ICMP stream can't be handled. Rejecting.");
		errno = EBADF;
		goto error;
	}

	/*
	 * Trying to connect to ANY address will evidently not work for Tor thus we
	 * deny the call.
	 */
	if (utils_is_addr_any(addr)) {
		errno = EINVAL;
		goto error;
	}

	DBG("[connect] Socket family %s and type %d",
			addr->sa_family == AF_INET ? "AF_INET" : "AF_INET6", sock_type);

	/*
	 * Lock registry to get the connection reference if one. In this code path,
	 * if a connection object is found, it will not be used since a double
	 * connect() on the same file descriptor is an error so the registry is
	 * quickly unlocked and no reference is needed.
	 */
	connection_registry_lock();
	new_conn = connection_find(sockfd);
	connection_registry_unlock();
	if (new_conn) {
		/* Double connect() for the same fd. */
		errno = EISCONN;
		goto error;
	}

	/*
	 * See if the IP being connected is an onion IP cookie mapping to an
	 * existing .onion address.
	 */
	onion_pool_lock(&tsocks_onion_pool);
	on_entry = onion_entry_find_by_addr(addr, &tsocks_onion_pool);
	onion_pool_unlock(&tsocks_onion_pool);
	if (on_entry) {
		/*
		 * Create a connection without a destination address since we will set
		 * the onion address name found before.
		 */
		new_conn = connection_create(sockfd, NULL);
		if (!new_conn) {
			errno = ENOMEM;
			goto error;
		}
		new_conn->dest_addr.domain = CONNECTION_DOMAIN_NAME;
		new_conn->dest_addr.hostname.port = utils_get_port_from_addr(addr);
		new_conn->dest_addr.hostname.addr = strdup(on_entry->hostname);
		if (!new_conn->dest_addr.hostname.addr) {
			errno = ENOMEM;
			goto error;
		}
	} else {
		/*
		 * Check if address is localhost. At this point, we are sure it's not a
		 * .onion cookie address that is by default in the loopback network.
		 */
		if (utils_sockaddr_is_localhost(addr)) {
			if (tsocks_config.allow_localhost) {
				goto libc_connect;
			}
			WARN("[connect] Connection to a local address are denied since it "
					"might be a TCP DNS query to a local DNS server. "
					"Rejecting it for safety reasons.");
			errno = EPERM;
			goto error;
		}

		new_conn = connection_create(sockfd, addr);
		if (!new_conn) {
			errno = ENOMEM;
			goto error;
		}
	}

	/* Connect the socket to the Tor network. */
	ret = tsocks_connect_to_tor(new_conn);
	if (ret < 0) {
		errno = -ret;
		goto error;
	}

	connection_registry_lock();
	/* This can't fail since a lookup was done previously. */
	connection_insert(new_conn);
	connection_registry_unlock();

	/* Flag errno for success */
	ret = errno = 0;
	return ret;

libc_connect:
	return tsocks_libc_connect(LIBC_CONNECT_ARGS);
error:
	/* At this point, errno MUST be set to a valid connect() error value. */
	return -1;
}

/*
 * Libc hijacked symbol connect(2).
 */
LIBC_CONNECT_DECL
{
	return tsocks_connect(LIBC_CONNECT_ARGS);
}
