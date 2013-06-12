/*
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
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
#include <errno.h>

#include <lib/torsocks.h>

#include "log.h"
#include "socks5.h"

/*
 * Receive data on a given file descriptor using recv(2). This handles partial
 * send and EINTR.
 *
 * Return the number of bytes received or a negative errno error.
 */
static ssize_t recv_data(int fd, void *buf, size_t len)
{
	ssize_t ret, read_len, read_left, index;

	assert(buf);
	assert(fd >= 0);

	read_left = len;
	index = 0;
	do {
		read_len = recv(fd, buf + index, read_left, 0);
		if (read_len < 0) {
			ret = -errno;
			if (errno == EINTR) {
				/* Try again after interruption. */
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (index) {
					/* Return the number of bytes received up to this point. */
					ret = index;
				}
				goto error;
			} else {
				PERROR("recv socks5 data");
				goto error;
			}
		}
		read_left -= read_len;
		index += read_len;
	} while (read_left > 0);

	/* Everything was received. */
	ret = index;

error:
	return ret;
}

/*
 * Send data to a given file descriptor using send(2). This handles partial
 * send and EINTR.
 *
 * Return the number of bytes sent or a negative errno error.
 */
static ssize_t send_data(int fd, const void *buf, size_t len)
{
	ssize_t ret, sent_len, sent_left, index;

	assert(buf);
	assert(fd >= 0);

	sent_left = len;
	index = 0;
	do {
		sent_len = send(fd, buf + index, sent_left, 0);
		if (sent_len < 0) {
			ret = -errno;
			if (errno == EINTR) {
				/* Send again after interruption. */
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (index) {
					/* Return the number of bytes sent up to this point. */
					ret = index;
				}
				goto error;
			} else {
				PERROR("send socks5 data");
				goto error;
			}
		}
		sent_left -= sent_len;
		index += sent_len;
	} while (sent_left > 0);

	/* Everything was sent. */
	ret = index;

error:
	return ret;
}

/*
 * Connect to socks5 server address in the connection object.
 *
 * Return 0 on success or else a negative value.
 */
int socks5_connect(struct connection *conn)
{
	int ret;
	struct sockaddr *socks5_addr = NULL;

	assert(conn);
	assert(conn->fd >= 0);

	switch (conn->socks5_addr.domain) {
	case CONNECTION_DOMAIN_INET:
		socks5_addr = (struct sockaddr *) &conn->socks5_addr.u.sin;
		break;
	case CONNECTION_DOMAIN_INET6:
		socks5_addr = (struct sockaddr *) &conn->socks5_addr.u.sin6;
		break;
	default:
		ERR("Socks5 connect domain unknown %d", conn->socks5_addr.domain);
		assert(0);
		ret = -EBADF;
		goto error;
	}

	/* Use the original libc connect() to the Tor. */
	ret = tsocks_libc_connect(conn->fd, socks5_addr, sizeof(*socks5_addr));
	if (ret < 0) {
		ret = -errno;
	}

error:
	return ret;
}

/*
 * Send socks5 method packet to server.
 *
 * Return 0 on success or else a negative errno value.
 */
int socks5_send_method(struct connection *conn)
{
	int ret = 0;
	ssize_t ret_send;
	struct socks5_method_req msg;

	assert(conn);
	assert(conn->fd >= 0);

	msg.ver = SOCKS5_VERSION;
	msg.nmethods = 0x01;
	msg.methods = SOCKS5_NO_AUTH_METHOD;

	DBG("Socks5 sending method ver: %d, nmethods 0x%02x, methods 0x%02x",
			msg.ver, msg.nmethods, msg.methods);

	ret_send = send_data(conn->fd, &msg, sizeof(msg));
	if (ret_send < 0) {
		ret = ret_send;
		goto error;
	}

error:
	return ret;
}

/*
 * Receive socks5 method response packet from server.
 *
 * Return 0 on success or else a negative errno value.
 */
int socks5_recv_method(struct connection *conn)
{
	int ret;
	ssize_t ret_recv;
	struct socks5_method_res msg;

	assert(conn);
	assert(conn->fd >= 0);

	ret_recv = recv_data(conn->fd, &msg, sizeof(msg));
	if (ret_recv < 0) {
		ret = ret_recv;
		goto error;
	}

	DBG("Socks5 received method ver: %d, method 0x%02x", msg.ver, msg.method);

	if (msg.ver != SOCKS5_VERSION ||
			msg.method == SOCKS5_NO_ACCPT_METHOD) {
		ret = -ECONNABORTED;
		goto error;
	}

	/* Successfully received. */
	ret = 0;

error:
	return ret;
}

/*
 * Send a connect request to the SOCKS5 server using the given connection and
 * the destination address in it pointing to the destination that needs to be
 * reached through Tor.
 *
 * Return 0 on success or else a negative value.
 */
int socks5_send_connect_request(struct connection *conn)
{
	int ret;
	/* Buffer to send won't go over a full TCP size. */
	char buffer[1500];
	ssize_t buf_len, ret_send;
	struct socks5_request msg;

	assert(conn);
	assert(conn->fd >= 0);

	memset(buffer, 0, sizeof(buffer));
	buf_len = sizeof(msg);

	msg.ver = SOCKS5_VERSION;
	msg.cmd = SOCKS5_CMD_CONNECT;
	/* Always zeroed. */
	msg.rsv = 0;

	/* Select connection socket domain. */
	if (conn->dest_addr.domain == CONNECTION_DOMAIN_INET) {
		struct socks5_request_ipv4 req_ipv4;

		msg.atyp = SOCKS5_ATYP_IPV4;
		/* Copy the first part of the request. */
		memcpy(buffer, &msg, buf_len);

		/* Prepare the ipv4 payload to be copied in the send buffer. */
		memcpy(req_ipv4.addr, &conn->dest_addr.u.sin.sin_addr,
				sizeof(req_ipv4.addr));
		req_ipv4.port = conn->dest_addr.u.sin.sin_port;

		/* Copy ipv4 request portion in the buffer. */
		memcpy(buffer + buf_len, &req_ipv4, sizeof(req_ipv4));
		buf_len += sizeof(req_ipv4);
	} else if (conn->dest_addr.domain == CONNECTION_DOMAIN_INET6) {
		struct socks5_request_ipv6 req_ipv6;

		msg.atyp = SOCKS5_ATYP_IPV6;
		/* Copy the first part of the request. */
		memcpy(buffer, &msg, buf_len);

		/* Prepare the ipv6 payload to be copied in the send buffer. */
		memcpy(req_ipv6.addr, &conn->dest_addr.u.sin6.sin6_addr,
				sizeof(req_ipv6.addr));
		req_ipv6.port = conn->dest_addr.u.sin6.sin6_port;

		/* Copy ipv6 request portion in the buffer. */
		memcpy(buffer + buf_len, &req_ipv6, sizeof(req_ipv6));
		buf_len += sizeof(req_ipv6);
	} else {
		ERR("Socks5 connection domain unknown %d", conn->dest_addr.domain);
		ret = -EINVAL;
		goto error;
	}

	DBG("Socks5 sending connect request to fd %d", conn->fd);

	ret_send = send_data(conn->fd, &buffer, buf_len);
	if (ret_send < 0) {
		ret = ret_send;
		goto error;
	}

	/* Data was sent successfully. */
	ret = 0;

error:
	return ret;
}

/*
 * Receive on the given connection the SOCKS5 connect reply.
 *
 * Return 0 on success or else a negative value.
 */
int socks5_recv_connect_reply(struct connection *conn)
{
	int ret;
	ssize_t ret_recv;
	struct socks5_reply msg;

	assert(conn);
	assert(conn >= 0);

	ret_recv = recv_data(conn->fd, &msg, sizeof(msg));
	if (ret_recv < 0) {
		ret = ret_recv;
		goto error;
	}

	DBG("Socks5 received connect reply - ver: %d, rep: 0x%02x, atype: 0x%02x",
			msg.ver, msg.rep, msg.atyp);

	switch (msg.rep) {
	case SOCKS5_REPLY_SUCCESS:
		DBG("Socks5 connection is successful.");
		ret = 0;
		break;
	case SOCKS5_REPLY_FAIL:
		ERR("General SOCKS server failure");
		ret = -ECONNREFUSED;
		break;
	case SOCKS5_REPLY_DENY_RULE:
		ERR("Connection not allowed by ruleset");
		ret = -ECONNABORTED;
		break;
	case SOCKS5_REPLY_NO_NET:
		ERR("Network unreachable");
		ret = -ENETUNREACH;
		break;
	case SOCKS5_REPLY_NO_HOST:
		ERR("Host unreachable");
		ret = -EHOSTUNREACH;
		break;
	case SOCKS5_REPLY_REFUSED:
		ERR("Connection refused to Tor SOCKS");
		ret = -ECONNREFUSED;
		break;
	case SOCKS5_REPLY_TTL_EXP:
		ERR("Connection timed out");
		ret = -ETIMEDOUT;
		break;
	case SOCKS5_REPLY_CMD_NOTSUP:
		ERR("Command not supported");
		ret = -ECONNREFUSED;
		break;
	case SOCKS5_REPLY_ADR_NOTSUP:
		ERR("Address type not supported");
		ret = -ECONNREFUSED;
		break;
	default:
		ERR("Socks5 server replied an unknown code %d", msg.rep);
		ret = -ECONNABORTED;
		break;
	}

error:
	return ret;
}
