/*
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
 *                      Luke Gallagher <luke@hypergeometric.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <common/connection.h>
#include <common/defaults.h>
#include <common/socks5.h>

#include <tap/tap.h>

#define NUM_TESTS 41

static struct socks5_method_req method_req;
static struct socks5_request req;
static struct socks5_request_ipv4 req_ipv4;
static struct socks5_request_ipv6 req_ipv6;
static struct socks5_request_domain req_name;
static struct socks5_request_resolve req_resolve;
static struct socks5_request_resolve_ptr req_resolve_ptr;

static struct connection *get_connection_stub(void)
{
	struct connection *conn = NULL;
	struct connection_addr c_addr;

	connection_addr_set(CONNECTION_DOMAIN_INET,
			DEFAULT_TOR_ADDRESS,
			DEFAULT_TOR_PORT,
			&c_addr);
	conn = connection_create(1, (struct sockaddr *) &c_addr.u.sin);

	return conn;
}

static struct connection *get_connection_ipv6_stub(void)
{
	struct connection *conn = NULL;
	struct connection_addr c_addr;

	connection_addr_set(CONNECTION_DOMAIN_INET6, "::1", 9050, &c_addr);
	conn = connection_create(1, (struct sockaddr *) &c_addr.u.sin6);

	return conn;
}

static struct connection *get_connection_domain_stub(void)
{
	struct connection *conn = NULL;
	char addr_str[] = "example.org";

	conn = connection_create(1, NULL);
	conn->dest_addr.domain = CONNECTION_DOMAIN_NAME;
	conn->dest_addr.hostname.addr = strndup(addr_str, strlen(addr_str));
	conn->dest_addr.hostname.port = htons(9050);

	return conn;
}

static void set_socks5_request(const void *buffer)
{
	req.ver = ((struct socks5_request *)buffer)->ver;
	req.cmd = ((struct socks5_request *)buffer)->cmd;
	req.rsv = ((struct socks5_request *)buffer)->rsv;
	req.atyp = ((struct socks5_request *)buffer)->atyp;
}

static ssize_t socks5_send_data_error_stub(int fd, const void *buf, size_t len)
{
	return -1;
}

static ssize_t socks5_recv_data_error_stub(int fd, void *buf, size_t len)
{
	return -1;
}

/*
 * socks5_send_method test doubles.
 */

static ssize_t socks5_send_method_valid_spy(int fd, const void *buf, size_t len)
{
	method_req.ver = ((struct socks5_method_req *)buf)->ver;
	method_req.nmethods = ((struct socks5_method_req *)buf)->nmethods;
	method_req.methods = ((struct socks5_method_req *)buf)->methods;

	return 1;
}

/*
 * socks5_recv_method test doubles.
 */

static ssize_t socks5_recv_method_valid_stub(int fd, void *buf, size_t len)
{
	((struct socks5_method_res *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_method_res *)buf)->method = SOCKS5_NO_AUTH_METHOD;

	return 1;
}

static ssize_t socks5_recv_method_wrong_version_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_method_res *)buf)->ver = 0x04;
	((struct socks5_method_res *)buf)->method = SOCKS5_NO_AUTH_METHOD;

	return 1;
}

static ssize_t socks5_recv_method_no_accept_stub(int fd, void *buf, size_t len)
{
	((struct socks5_method_res *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_method_res *)buf)->method = SOCKS5_NO_ACCPT_METHOD;

	return 1;
}

/*
 * send_connect_request test doubles
 */

static ssize_t socks5_send_connect_request_ipv4_spy(int fd, const void *buf,
		size_t len)
{
	ssize_t buf_len = 0;

	set_socks5_request(buf);
	buf_len += sizeof(struct socks5_request);

	req_ipv4 = (*(struct socks5_request_ipv4 *) (buf + buf_len));

	return 1;
}

static ssize_t socks5_send_connect_request_ipv6_spy(int fd, const void *buf,
		size_t len)
{
	ssize_t buf_len = 0;

	set_socks5_request(buf);
	buf_len += sizeof(struct socks5_request);

	req_ipv6 = (*(struct socks5_request_ipv6 *) (buf + buf_len));

	return 1;
}

static ssize_t socks5_send_connect_request_domain_spy(int fd, const void *buf,
		size_t len)
{
	ssize_t buf_len = 0;

	set_socks5_request(buf);
	buf_len += sizeof(struct socks5_request);

	/*
	 * Use memcpy since req_name.name is variable length.
	 */
	memcpy(&req_name.len, buf + buf_len, sizeof(req_name.len));
	buf_len += sizeof(req_name.len);
	memcpy(&req_name.name, buf + buf_len, req_name.len);
	buf_len += req_name.len;
	memcpy(&req_name.port, buf + buf_len, sizeof(req_name.port));

	return 1;
}

/*
 * socks5_receive_connect_reply test doubles.
 */

static ssize_t socks5_recv_connect_reply_ipv4_success_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_fail_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_FAIL;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_deny_rule_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_DENY_RULE;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_no_net_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_NO_NET;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_no_host_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_NO_HOST;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_refused_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_REFUSED;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_ttl_expired_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_TTL_EXP;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_cmd_not_supported_stub(int fd,
		void *buf, size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_CMD_NOTSUP;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_addr_not_supported_stub(int fd,
		void *buf, size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_ADR_NOTSUP;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv4_unkown_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = 0x9; /* unassigned code */
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_connect_reply_ipv6_success_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV6;

	return 1;
}

/*
 * socks5_send_resolve_request test doubles.
 */

static ssize_t socks5_send_resolve_request_valid_spy(int fd, const void *buf,
		size_t len)
{
	ssize_t buf_len = 0;

	set_socks5_request(buf);
	buf_len += sizeof(struct socks5_request);

	memcpy(&req_resolve.len, buf + buf_len, sizeof(req_resolve.len));
	buf_len += sizeof(req_resolve.len);
	memcpy(&req_resolve.name, buf + buf_len, req_resolve.len);

	return 1;
}

/*
 * socks5_recv_resolve_reply test doubles.
 */

static ssize_t socks5_recv_resolve_reply_ipv4_stub(int fd, void *buf,
		size_t len)
{
	static int count = 0;
	uint8_t ipv4_stub[4];

	if (0 == count) {
		/* first call to recv_data */
		((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
		((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
		((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;
	} else {
		/* second call to recv data */
		inet_pton(AF_INET, "127.0.0.1", &ipv4_stub);
		memcpy(buf, &ipv4_stub, len);
	}

	count++;

	return 1;
}

static ssize_t socks5_recv_resolve_reply_ipv6_stub(int fd, void *buf,
		size_t len)
{
	static int count = 0;
	uint8_t ipv6_stub[16];

	if (0 == count) {
		/* first call to recv_data */
		((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
		((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
		((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV6;
	} else {
		/* second call to recv data */
		inet_pton(AF_INET6, "::1", &ipv6_stub);
		memcpy(buf, &ipv6_stub, len);
	}

	count++;

	return 1;
}

static ssize_t socks5_recv_resolve_reply_incorrect_version_stub(int fd,
		void *buf, size_t len)
{
	((struct socks5_reply *)buf)->ver = 0x04;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_resolve_reply_response_error_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_FAIL;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

static ssize_t socks5_recv_resolve_reply_address_type_error_stub(int fd,
		void *buf, size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_DOMAIN;

	return 1;
}

static ssize_t socks5_recv_resolve_reply_addrlen_error_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 10;
}

/*
 * socks5_send_resolve_ptr_request test doubles.
 */

static ssize_t socks5_send_resolve_ptr_request_ipv4_spy(int fd,
		const void *buf, size_t len)
{
	int buf_len = 0;

	set_socks5_request(buf);
	buf_len += sizeof(struct socks5_request);

	req_resolve_ptr = (*(struct socks5_request_resolve_ptr *) (buf + buf_len));

	return 1;
}

static ssize_t socks5_send_resolve_ptr_request_ipv6_spy(int fd,
		const void *buf, size_t len)
{
	int buf_len = 0;

	set_socks5_request(buf);
	buf_len += sizeof(struct socks5_request);

	req_resolve_ptr = (*(struct socks5_request_resolve_ptr *) (buf + buf_len));

	return 1;
}

/*
 * socks5_recv_resolve_ptr_reply test doubles.
 */

static ssize_t socks5_recv_resolve_ptr_reply_stub(int fd, void *buf,
		size_t len)
{
	static int count = 0;
	int buf_len = 0;
	char hostname[] = "example.org";

	if (0 == count) {
		/* first call to recv_data */
		((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
		((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
		((struct socks5_reply *)buf)->rsv = 0;
		((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_DOMAIN;

		buf_len += sizeof(struct socks5_reply);
		(*(uint8_t *)(buf + buf_len)) = strlen(hostname);
	} else {
		/* second call to recv data */
		memcpy(buf, &hostname, len);
	}

	count++;

	return 1;
}

static ssize_t socks5_recv_resolve_ptr_reply_atyp_error_stub(int fd, void *buf,
		size_t len)
{
	((struct socks5_reply *)buf)->ver = SOCKS5_VERSION;
	((struct socks5_reply *)buf)->rep = SOCKS5_REPLY_SUCCESS;
	((struct socks5_reply *)buf)->rsv = 0;
	((struct socks5_reply *)buf)->atyp = SOCKS5_ATYP_IPV4;

	return 1;
}

/*
 * socks5 tests
 */

static void test_socks5_send_method_valid(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(socks5_send_method_valid_spy, NULL);

	ret = socks5_send_method(conn_stub, SOCKS5_NO_AUTH_METHOD);

	ok(ret == 0 &&
		method_req.ver == SOCKS5_VERSION &&
		method_req.nmethods == 0x01 &&
		method_req.methods == SOCKS5_NO_AUTH_METHOD,
		"socks5 send method valid");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_send_method_failure(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(socks5_send_data_error_stub, NULL);

	ret = socks5_send_method(conn_stub, SOCKS5_NO_AUTH_METHOD);

	ok(ret == -1, "socks5 send method returns send error code");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_method_valid(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_method_valid_stub);

	ret = socks5_recv_method(conn_stub);

	ok(ret == 0, "socks5 recv method valid response");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_method_failure(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_data_error_stub);

	ret = socks5_recv_method(conn_stub);

	ok(ret == -1, "socks5 recv method returns recv error code");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_method_incorrect_version(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_method_wrong_version_stub);

	ret = socks5_recv_method(conn_stub);

	ok(ret == -ECONNABORTED, "socks5 recv method returns ECONNABORTED when "
		"incorrect version");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_method_no_accept(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_method_no_accept_stub);

	ret = socks5_recv_method(conn_stub);

	ok(ret == -ECONNABORTED, "socks5 recv method returns ECONNABORTED when "
		"no accept method");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_send_connect_request(void)
{
	int ret;
	struct connection *conn_stub;
	char ip[INET6_ADDRSTRLEN];

	conn_stub = get_connection_stub();
	socks5_init(socks5_send_connect_request_ipv4_spy, NULL);

	ret = socks5_send_connect_request(conn_stub);

	inet_ntop(AF_INET,
		(struct sockaddr_in *)&req_ipv4.addr,
		ip, INET6_ADDRSTRLEN);

	ok(ret == 0 &&
		req.ver == SOCKS5_VERSION &&
		req.cmd == SOCKS5_CMD_CONNECT &&
		req.rsv == 0 &&
		req.atyp == SOCKS5_ATYP_IPV4 &&
		strncmp(ip, "127.0.0.1", INET6_ADDRSTRLEN) == 0 &&
		req_ipv4.port == htons(9050),
		"socks5 send connect request IPv4");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);

	/* IPv6 */

	conn_stub = get_connection_ipv6_stub();
	socks5_init(socks5_send_connect_request_ipv6_spy, NULL);

	ret = socks5_send_connect_request(conn_stub);

	inet_ntop(AF_INET6,
		(struct sockaddr_in *)&req_ipv6.addr,
		ip, INET6_ADDRSTRLEN);

	ok(ret == 0 &&
		req.ver == SOCKS5_VERSION &&
		req.cmd == SOCKS5_CMD_CONNECT &&
		req.rsv == 0 &&
		req.atyp == SOCKS5_ATYP_IPV6 &&
		strncmp(ip, "::1", INET6_ADDRSTRLEN) == 0 &&
		req_ipv6.port == htons(9050),
		"socks5 send connect request IPv6");

	/* Domain name */

	conn_stub = get_connection_domain_stub();
	socks5_init(socks5_send_connect_request_domain_spy, NULL);

	ret = socks5_send_connect_request(conn_stub);

	ok(ret == 0 &&
		req.ver == SOCKS5_VERSION &&
		req.cmd == SOCKS5_CMD_CONNECT &&
		req.rsv == 0 &&
		req.atyp == SOCKS5_ATYP_DOMAIN &&
		strncmp((char *)req_name.name,
			"example.org",
			req_name.len) == 0 &&
		req_name.port == htons(9050),
		"socks5 send connect request domain name");

	/* Unkown connection domain */

	conn_stub = get_connection_stub();
	conn_stub->dest_addr.domain = 0;
	socks5_init(socks5_send_connect_request_domain_spy, NULL);

	ret = socks5_send_connect_request(conn_stub);

	ok(ret == -EINVAL, "socks5 send connect request returns error for "
		"unkown connection domain");
	connection_destroy(conn_stub);
}

static void test_socks5_send_connect_request_failure(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(socks5_send_data_error_stub, NULL);

	ret = socks5_send_connect_request(conn_stub);

	ok(ret == -1, "socks5 connect request returns error code from send");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_success(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv4_success_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == 0, "socks5 reply success");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_fail(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv4_fail_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -ECONNREFUSED, "socks5 reply fail");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_deny_rule(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv4_deny_rule_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -ECONNABORTED, "socks5 reply deny rule");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_no_net(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv4_no_net_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -ENETUNREACH, "socks5 reply no net");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_no_host(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv4_no_host_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -EHOSTUNREACH, "socks5 reply no host");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_refused(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv4_refused_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -ECONNREFUSED, "socks5 reply refused");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_ttl_expired(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv4_ttl_expired_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -ETIMEDOUT, "socks5 reply TTL expired");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_cmd_not_supported(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL,
			socks5_recv_connect_reply_ipv4_cmd_not_supported_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -ECONNREFUSED, "socks5 reply command not supported");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_addr_not_supported(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL,
			socks5_recv_connect_reply_ipv4_addr_not_supported_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -ECONNREFUSED, "socks5 reply address type not supported");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_unkown(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv4_unkown_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == -ECONNABORTED, "socks5 reply unkown code");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_connect_reply_ipv6_success(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_connect_reply_ipv6_success_stub);

	ret = socks5_recv_connect_reply(conn_stub);

	ok(ret == 0, "socks5 reply IPv6 success");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_send_resolve_request_valid(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(socks5_send_resolve_request_valid_spy, NULL);

	ret = socks5_send_resolve_request("foo", conn_stub);

	ok(ret == 0 &&
		req.ver == SOCKS5_VERSION &&
		req.cmd == SOCKS5_CMD_RESOLVE &&
		req.rsv == 0 &&
		req.atyp == SOCKS5_ATYP_DOMAIN &&
		strcmp((char *)req_resolve.name, "foo") == 0 &&
		req_resolve.len == strlen("foo"),
		"socks5 resolve request valid");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_send_resolve_request_failure(void)
{
	int ret;
	struct connection *conn_stub;

	conn_stub = get_connection_stub();
	socks5_init(socks5_send_data_error_stub, NULL);

	ret = socks5_send_resolve_request("foo", conn_stub);

	ok(ret == -1, "socks5 resolve request returns send error code");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);

	/* hostname greater than 255 in length */

	conn_stub = get_connection_stub();
	/* no need to stub send_data it should not get called */

	char long_hostname[257];
	memset(long_hostname, 0x41, sizeof(long_hostname));
	long_hostname[256] = '\0';

	ret = socks5_send_resolve_request(long_hostname, conn_stub);

	ok(ret == -EINVAL, "socks5 resolve request hostname greater "
		"than UINT8_MAX");

	connection_destroy(conn_stub);
}

static void test_socks5_recv_resolve_reply_valid(void)
{
	int ret;
	struct connection *conn_stub;
	uint32_t ipv4_addr;
	uint8_t ipv6_addr[16];
	char ip_str[INET6_ADDRSTRLEN];

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_reply_ipv4_stub);

	ret = socks5_recv_resolve_reply(conn_stub, &ipv4_addr, sizeof(uint32_t));

	inet_ntop(AF_INET, &ipv4_addr, ip_str, INET_ADDRSTRLEN);

	ok(ret == 0 &&
		strncmp(ip_str, "127.0.0.1", INET_ADDRSTRLEN) == 0,
		"socks5 resolve reply valid IPv4 address");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);

	/* IPv6 */

	conn_stub = get_connection_ipv6_stub();
	socks5_init(NULL, socks5_recv_resolve_reply_ipv6_stub);

	ret = socks5_recv_resolve_reply(conn_stub, &ipv6_addr, sizeof(ipv6_addr));

	inet_ntop(AF_INET6, &ipv6_addr, ip_str, INET6_ADDRSTRLEN);

	ok(ret == 0 &&
		strncmp(ip_str, "::1", INET6_ADDRSTRLEN) == 0,
		"socks5 resolve reply valid IPv6 address");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_resolve_reply_failure(void)
{
	int ret;
	struct connection *conn_stub;
	uint32_t dummy_ip_addr;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_data_error_stub);

	ret = socks5_recv_resolve_reply(conn_stub, &dummy_ip_addr,
			sizeof(dummy_ip_addr));

	ok(ret == -1, "socks5 resolve reply returns recv error code");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_resolve_reply_incorrect_version(void)
{
	int ret;
	struct connection *conn_stub;
	uint32_t dummy_ip_addr;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_reply_incorrect_version_stub);

	ret = socks5_recv_resolve_reply(conn_stub, &dummy_ip_addr,
			sizeof(dummy_ip_addr));

	ok(ret == -ECONNABORTED, "socks5 resolve reply incorrect version");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_resolve_reply_response_error(void)
{
	int ret;
	struct connection *conn_stub;
	uint32_t dummy_ip_addr;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_reply_response_error_stub);

	ret = socks5_recv_resolve_reply(conn_stub, &dummy_ip_addr,
			sizeof(dummy_ip_addr));

	ok(ret == -ECONNABORTED, "socks5 resolve reply response error");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_resolve_reply_address_type_error(void)
{
	int ret;
	struct connection *conn_stub;
	uint32_t dummy_ip_addr;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_reply_address_type_error_stub);

	ret = socks5_recv_resolve_reply(conn_stub, &dummy_ip_addr,
			sizeof(dummy_ip_addr));

	ok(ret == -EINVAL, "socks5 resolve reply address type error");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_recv_resolve_reply_addrlen_error(void)
{
	int ret;
	struct connection *conn_stub;
	uint32_t dummy_ip_addr;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_reply_addrlen_error_stub);

	ret = socks5_recv_resolve_reply(conn_stub, &dummy_ip_addr, 1);

	ok(ret == -EINVAL, "socks5 resolve reply address length error");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_send_resolve_ptr_request_valid(void)
{
	int ret;
	struct connection *conn_stub;
	uint32_t ipv4_addr_stub;
	uint8_t ipv6_addr_stub[16];
	char ip_str[INET6_ADDRSTRLEN];

	conn_stub = get_connection_stub();
	socks5_init(socks5_send_resolve_ptr_request_ipv4_spy, NULL);
	inet_pton(AF_INET, "127.0.0.1", &ipv4_addr_stub);

	ret = socks5_send_resolve_ptr_request(conn_stub, &ipv4_addr_stub, AF_INET);

	inet_ntop(AF_INET, &req_resolve_ptr, ip_str, INET_ADDRSTRLEN);

	ok(ret == 0 &&
		req.ver == SOCKS5_VERSION &&
		req.cmd == SOCKS5_CMD_RESOLVE_PTR &&
		req.rsv == 0 &&
		req.atyp == SOCKS5_ATYP_IPV4 &&
		strncmp(ip_str, "127.0.0.1", INET_ADDRSTRLEN) == 0,
		"socks5 send resolve ptr request valid IPv4");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);

	/* IPv6 */

	conn_stub = get_connection_ipv6_stub();
	socks5_init(socks5_send_resolve_ptr_request_ipv6_spy, NULL);
	inet_pton(AF_INET6, "::1", ipv6_addr_stub);

	ret = socks5_send_resolve_ptr_request(conn_stub, ipv6_addr_stub, AF_INET6);

	inet_ntop(AF_INET6, ipv6_addr_stub, ip_str, INET6_ADDRSTRLEN);

	ok(ret == 0 &&
		req.ver == SOCKS5_VERSION &&
		req.cmd == SOCKS5_CMD_RESOLVE_PTR &&
		req.rsv == 0 &&
		req.atyp == SOCKS5_ATYP_IPV6 &&
		strncmp(ip_str, "::1", INET6_ADDRSTRLEN) == 0,
		"socks5 send resolve ptr request valid IPv6");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
}

static void test_socks5_send_resolve_ptr_request_failure(void)
{
	int ret;
	struct connection *conn_stub;
	uint32_t addr_stub;

	conn_stub = get_connection_stub();
	socks5_init(socks5_send_data_error_stub, NULL);
	inet_pton(AF_INET, "127.0.0.1", &addr_stub);

	ret = socks5_send_resolve_ptr_request(conn_stub, &addr_stub, AF_INET);

	ok(ret == -1, "socks5 resolve ptr request returns send error code");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);

	/* Unkown domain */

	conn_stub = get_connection_domain_stub();

	ret = socks5_send_resolve_ptr_request(conn_stub, &addr_stub, 3);

	ok(ret == -EINVAL, "socks5 send resolve ptr request unkown domain");

	connection_destroy(conn_stub);
}

static void test_socks5_recv_resolve_ptr_reply_valid(void)
{
	int ret;
	struct connection *conn_stub;
	char *hostname = NULL;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_ptr_reply_stub);

	ret = socks5_recv_resolve_ptr_reply(conn_stub, &hostname);

	ok(ret == 0 &&
		strncmp(hostname, "example.org", strlen(hostname)) == 0,
	   	"socks5 recv resolve ptr reply valid");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
	free(hostname);
}

static void test_socks5_recv_resolve_ptr_reply_failure(void)
{
	int ret;
	struct connection *conn_stub;
	char *hostname = NULL;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_data_error_stub);

	ret = socks5_recv_resolve_ptr_reply(conn_stub, &hostname);

	ok(ret == -1, "socks5 recv resolve ptr reply returns recv error code");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
	free(hostname);
}

static void test_socks5_recv_resolve_ptr_reply_incorrect_version(void)
{
	int ret;
	struct connection *conn_stub;
	char *hostname = NULL;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_reply_incorrect_version_stub);

	ret = socks5_recv_resolve_ptr_reply(conn_stub, &hostname);

	ok(ret == -ECONNABORTED, "socks5 recv resolve ptr reply incorrect version");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
	free(hostname);
}

static void test_socks5_recv_resolve_ptr_reply_response_error(void)
{
	int ret;
	struct connection *conn_stub;
	char *hostname = NULL;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_reply_response_error_stub);

	ret = socks5_recv_resolve_ptr_reply(conn_stub, &hostname);

	ok(ret == -ECONNABORTED, "socks5 recv resolve ptr reply response error");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
	free(hostname);
}

static void test_socks5_recv_resolve_ptr_reply_atyp_error(void)
{
	int ret;
	struct connection *conn_stub;
	char *hostname = NULL;

	conn_stub = get_connection_stub();
	socks5_init(NULL, socks5_recv_resolve_ptr_reply_atyp_error_stub);

	ret = socks5_recv_resolve_ptr_reply(conn_stub, &hostname);

	ok(ret == -EINVAL, "socks5 recv resolve ptr reply atyp error");

	connection_destroy(conn_stub);
	socks5_init(NULL, NULL);
	free(hostname);
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	diag("socks5 tests");

	test_socks5_send_method_valid();
	test_socks5_send_method_failure();
	test_socks5_recv_method_valid();
	test_socks5_recv_method_failure();
	test_socks5_recv_method_incorrect_version();
	test_socks5_recv_method_no_accept();
	test_socks5_send_connect_request();
	test_socks5_send_connect_request_failure();
	test_socks5_recv_connect_reply_success();
	test_socks5_recv_connect_reply_fail();
	test_socks5_recv_connect_reply_deny_rule();
	test_socks5_recv_connect_reply_no_net();
	test_socks5_recv_connect_reply_no_host();
	test_socks5_recv_connect_reply_refused();
	test_socks5_recv_connect_reply_ttl_expired();
	test_socks5_recv_connect_reply_cmd_not_supported();
	test_socks5_recv_connect_reply_addr_not_supported();
	test_socks5_recv_connect_reply_unkown();
	test_socks5_recv_connect_reply_ipv6_success();
	test_socks5_send_resolve_request_valid();
	test_socks5_send_resolve_request_failure();
	test_socks5_recv_resolve_reply_valid();
	test_socks5_recv_resolve_reply_failure();
	test_socks5_recv_resolve_reply_incorrect_version();
	test_socks5_recv_resolve_reply_response_error();
	test_socks5_recv_resolve_reply_address_type_error();
	test_socks5_recv_resolve_reply_addrlen_error();
	test_socks5_send_resolve_ptr_request_valid();
	test_socks5_send_resolve_ptr_request_failure();
	test_socks5_recv_resolve_ptr_reply_valid();
	test_socks5_recv_resolve_ptr_reply_failure();
	test_socks5_recv_resolve_ptr_reply_incorrect_version();
	test_socks5_recv_resolve_ptr_reply_response_error();
	test_socks5_recv_resolve_ptr_reply_atyp_error();

	return exit_status();
}
