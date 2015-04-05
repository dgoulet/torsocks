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
 * Validate the given sock fd and address that we receive in the connect()
 * call. Criteria are:
 *
 * 	-) Non INET/INET6 socket should return to the libc, LIBC.
 *	-) Non stream socket can't be handled, DENY.
 *	-) Connection to the any address won't work with Tor, DENY.
 *	-) ALLOW.
 *
 * Return 0 if validation passes and socket handling should continue. Return 1
 * if the socket can't be handle by Tor but is still valid thus the caller
 * should send it directly to the libc connect function.
 *
 * On error or if validation fails, errno is set and -1 is returned. The caller
 * should *return* right away an error.
 */
static int validate_socket(int sockfd, const struct sockaddr *addr)
{
	int ret, sock_type;
	socklen_t optlen;

	if (!addr) {
		/* Go directly to libc, connect() will handle a NULL value. */
		goto libc_call;
	}

	/*
	 * We can't handle a non inet socket thus directly go to the libc. This is
	 * to allow AF_UNIX/_LOCAL socket to work with torsocks.
	 */
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
		DBG("[conect] Connection is not IPv4/v6. Ignoring.");
		/* Ask the call to use the libc connect. */
		goto libc_call;
	}

	optlen = sizeof(sock_type);
	ret = getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen);
	if (ret < 0) {
		DBG("[connect] Fail getsockopt() on sock %d", sockfd);
		errno = EBADF;
		goto error;
	}

	DBG("[connect] Socket family %s and type %d",
			addr->sa_family == AF_INET ? "AF_INET" : "AF_INET6", sock_type);

	/* Refuse non stream socket since Tor can't handle that. */
	if (!IS_SOCK_STREAM(sock_type)) {
		DBG("[connect] UDP or ICMP stream can't be handled. Rejecting.");
		errno = EPERM;
		goto error;
	}

	/*
	 * Trying to connect to ANY address will evidently not work for Tor thus we
	 * deny the call with an invalid argument error.
	 */
	if (utils_is_addr_any(addr)) {
		errno = EPERM;
		goto error;
	}

	return 0;

libc_call:
	return 1;
error:
	return -1;
}

/*
 * Torsocks call for connect(2).
 */
LIBC_CONNECT_RET_TYPE tsocks_connect(LIBC_CONNECT_SIG)
{
	int ret, ret_errno;
	struct connection *new_conn;
	struct onion_entry *on_entry;

	DBG("Connect catched on fd %d", sockfd);

	/*
	 * Validate socket values in order to see if we can handle this connect
	 * through Tor.
	 */
	ret = validate_socket(sockfd, addr);
	if (ret == 1) {
		/* Tor can't handle it so send it to the libc. */
		goto libc_connect;
	} else if (ret == -1) {
		/* Validation failed. Stop right now. */
		goto error;
	}
	/* Implicit else statement meaning we continue processing the connect. */
	assert(!ret);

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
			ret_errno = ENOMEM;
			goto error_free;
		}
	} else {
		/*
		 * Check if address is localhost. At this point, we are sure it's not a
		 * .onion cookie address that is by default in the loopback network
		 * thus this check is done after the onion entry lookup.
		 */
		if (utils_sockaddr_is_localhost(addr)) {
			/*
			 * Certain setups need to be able to reach localhost, despite
			 * running torsocks. If they enabled the config option, allow such
			 * connections.
			 */
			if (tsocks_config.allow_outbound_localhost) {
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
		ret_errno = -ret;
		goto error_free;
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

error_free:
	/*
	 * Put back reference of newly created connection. Will be freed if
	 * refcount goes down to 0.
	 */
	connection_put_ref(new_conn);
	errno = ret_errno;
error:
	/* At this point, errno MUST be set to a valid connect() error value. */
	return -1;
}

/*
 * Libc hijacked symbol connect(2).
 */
LIBC_CONNECT_DECL
{
	if (!tsocks_libc_connect)
		tsocks_initialize();
	return tsocks_connect(LIBC_CONNECT_ARGS);
}
