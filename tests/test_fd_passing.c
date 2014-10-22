/*
 * Copyright (C) 2014 - David Goulet <dgoulet@ev0ke.net>
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
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <sys/un.h>

#include <lib/torsocks.h>

#include <tap/tap.h>

#define NUM_TESTS 5

/*
 * Indicate if the thread recv is ready. 0 means no, 1 means yes and -1 means
 * error occured.
 */
static volatile int thread_recv_ready;

/* Unix socket for this test. */
static const char *sockpath = "/tmp/torsocks-unix-fd-passing.sock";

/* Order libtap output. */
static pthread_mutex_t tsocks_test_log = PTHREAD_MUTEX_INITIALIZER;
#define OK(cond, args...) \
	do {	\
		pthread_mutex_lock(&tsocks_test_log);	\
		ok(cond, ## args);			\
		pthread_mutex_unlock(&tsocks_test_log);	\
	} while (0);

/*
 * Send buf data of size len. Using sendmsg API.
 *
 * Return the size of sent data.
 */
static ssize_t send_unix_sock(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		/*
		 * Only warn about EPIPE when quiet mode is deactivated.
		 * We consider EPIPE as expected.
		 */
		if (errno != EPIPE) {
			perror("sendmsg");
		}
	}

	return ret;
}

static ssize_t send_fds_unix_sock(int sock, int *fds, size_t nb_fd)
{
	struct msghdr msg;
	struct cmsghdr *cmptr;
	struct iovec iov[1];
	ssize_t ret = -1;
	unsigned int sizeof_fds = nb_fd * sizeof(int);
	char tmp[CMSG_SPACE(sizeof_fds)];
	char dummy = 0;

	memset(&msg, 0, sizeof(msg));

	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof_fds);

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;
	cmptr->cmsg_len = CMSG_LEN(sizeof_fds);
	memcpy(CMSG_DATA(cmptr), fds, sizeof_fds);
	/* Sum of the length of all control messages in the buffer: */
	msg.msg_controllen = cmptr->cmsg_len;

	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	do {
		ret = sendmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		/*
		 * Only warn about EPIPE when quiet mode is deactivated.
		 * We consider EPIPE as expected.
		 */
		if (errno != EPIPE) {
			perror("sendmsg");
		}
	}
	return ret;
}

/*
 * Receive data of size len in put that data into the buf param. Using recvmsg
 * API.
 *
 * Return the size of received data.
 */
static ssize_t recv_unix_sock(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;
	size_t len_last;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	do {
		len_last = iov[0].iov_len;
		ret = recvmsg(sock, &msg, 0);
		if (ret > 0) {
			iov[0].iov_base += ret;
			iov[0].iov_len -= ret;
			assert(ret <= len_last);
		}
	} while ((ret > 0 && ret < len_last) || (ret < 0 && errno == EINTR));
	if (ret < 0) {
		perror("recvmsg");
	} else if (ret > 0) {
		ret = len;
	}
	/* Else ret = 0 meaning an orderly shutdown. */

	return ret;
}

/*
 * Recv a message accompanied by fd(s) from a unix socket.
 *
 * Returns the size of received data, or negative error value.
 *
 * Expect at most "nb_fd" file descriptors. Returns the number of fd
 * actually received in nb_fd.
 */
static ssize_t recv_fds_unix_sock(int sock, int *fds, size_t nb_fd)
{
	struct iovec iov[1];
	ssize_t ret = 0;
	struct cmsghdr *cmsg;
	size_t sizeof_fds = nb_fd * sizeof(int);
	char recv_fd[CMSG_SPACE(sizeof_fds)];
	struct msghdr msg;
	char dummy;

	memset(&msg, 0, sizeof(msg));

	/* Prepare to receive the structures */
	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = recv_fd;
	msg.msg_controllen = sizeof(recv_fd);

	do {
		ret = recvmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		goto end;
	}
	if (ret != 1) {
		fprintf(stderr, "Error: Received %zd bytes, expected %d\n",
				ret, 1);
		goto end;
	}
	if (msg.msg_flags & MSG_CTRUNC) {
		fprintf(stderr, "Error: Control message truncated.\n");
		ret = -1;
		goto end;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		fprintf(stderr, "Error: Invalid control message header\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "Didn't received any fd\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_len != CMSG_LEN(sizeof_fds)) {
		fprintf(stderr, "Error: Received %zu bytes of ancillary data, expected %zu\n",
				(size_t) cmsg->cmsg_len, (size_t) CMSG_LEN(sizeof_fds));
		ret = -1;
		goto end;
	}
	memcpy(fds, CMSG_DATA(cmsg), sizeof_fds);
	ret = sizeof_fds;
end:
	return ret;
}

/*
 * Connect to unix socket using the path name.
 */
static int connect_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd, ret, closeret;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		ret = fd;
		goto error;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, sizeof(sun.sun_path));
	sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

	ret = connect(fd, (struct sockaddr *) &sun, sizeof(sun));
	if (ret < 0) {
		/*
		 * Don't print message on connect error, because connect is used in
		 * normal execution to detect if sessiond is alive.
		 */
		goto error_connect;
	}

	return fd;

error_connect:
	closeret = close(fd);
	if (closeret) {
		perror("close");
	}
error:
	return ret;
}

/*
 * Creates a AF_UNIX local socket using pathname bind the socket upon creation
 * and return the fd.
 */
static int create_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd;
	int ret = -1;

	/* Create server socket */
	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		goto error;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, sizeof(sun.sun_path));
	sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

	/* Unlink the old file if present */
	(void) unlink(pathname);
	ret = bind(fd, (struct sockaddr *) &sun, sizeof(sun));
	if (ret < 0) {
		perror("bind");
		goto error;
	}

	return fd;

error:
	return ret;
}

/*
 * Do an accept(2) on the sock and return the new file descriptor. The socket
 * MUST be bind(2) before.
 */
static int accept_unix_sock(int sock)
{
	int new_fd;
	struct sockaddr_un sun;
	socklen_t len = 0;

	/* Blocking call */
	new_fd = accept(sock, (struct sockaddr *) &sun, &len);
	if (new_fd < 0) {
		perror("accept");
	}

	return new_fd;
}

void *thread_recv(void *data)
{
	int ret, new_sock, sock, fds[3] = {-1, -1, -1};
	char buf[4];
	ssize_t len;

	sock = create_unix_sock(sockpath);
	if (sock < 0) {
		fail("Create unix socket at %s", sockpath);
		goto error;
	}

	OK(sock >= 0, "Unix socket %d created at %s", sock, sockpath);

	ret = listen(sock, 10);
	if (ret < 0) {
		fail("Listen on unix socket %d", sock);
		goto error;
	}

	/* Notify we are ready to test. */
	thread_recv_ready = 1;

	new_sock = accept_unix_sock(sock);
	if (new_sock < 0) {
		fail("Accept on unix sock %d", sock);
		close(sock);
		goto error;
	}

	/* First receive a normal message saying "hello" to make sure the recvmsg
	 * call is not borked. */
	len = recv_unix_sock(new_sock, buf, sizeof(buf));
	if (len < 0) {
		fail("Recv normal data failed");
		goto error;
	}
	OK(len == sizeof(buf) &&
		strncmp(buf, "hello", sizeof(buf)) == 0,
		"Data received successfully");

	len = recv_fds_unix_sock(new_sock, fds, 3);
	if (len < 0) {
		/* This is suppose to fail with a errno set to EACCESS. */
		OK(errno == EACCES,
				"Passing INET socket denied.");
	} else {
		fail("Received INET socket through the unix socket");
	}

	close(sock);
	close(new_sock);
	close(fds[0]);
	close(fds[1]);
	close(fds[2]);

error:
	thread_recv_ready = -1;
	return NULL;
}

void *thread_send(void *data)
{
	int sock, fds[3], pipe_fds[2];
	ssize_t len;

	sock = connect_unix_sock(sockpath);
	if (sock < 0) {
		fail("Unable to connect to unix socket at %s", sockpath);
		goto error;
	}

	if (pipe(pipe_fds) < 0) {
		fail("Unable to create pipe");
		goto error;
	}

	/* First send regular data. */
	len = send_unix_sock(sock, "hello", 4);
	if (len < 0) {
		fail("Sending regular data.");
		goto error;
	}

	/*
	 * We are going to pass 3 fds, two of them are pipse in position 0 and 2
	 * and the inet socket is at position 1.
	 */
	fds[0] = pipe_fds[0];
	fds[1] = *((int *)data);
	fds[2] = pipe_fds[1];

	len = send_fds_unix_sock(sock, fds, 3);
	if (len < 0) {
		fail("Send inet socket through Unix sock");
		goto error;
	}
	OK(len == 1, "Inet socket %d sent successfully.", fds[1]);

error:
	if (sock >= 0) {
		close(sock);
	}
	if (pipe_fds[0] >= 0) {
		close(pipe_fds[0]);
	}
	if (pipe_fds[1] >= 0) {
		close(pipe_fds[1]);
	}
	return NULL;
}

/*
 * This test will spawn two thread, one accepting a Unix socket connection
 * which will recv the fd(s). The second thread will connect and send the fds.
 * Usually this is between processes but for the sake of the test threads are
 * enough.
 */
static void test_inet_socket(void)
{
	int ret, i, inet_sock = -1;
	void *status;
	pthread_t th[2];
	struct sockaddr_in addr;
	const char *ip = "93.95.227.222";

	/*
	 * First of all, we are going to try to create an inet socket to a public
	 * known IP being www.torproject.org --> 93.95.227.222.
	 */
	inet_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (inet_sock < 0) {
		fail("Creating inet socket");
		goto error;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(443);
	inet_pton(addr.sin_family, ip, &addr.sin_addr);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	ret = connect(inet_sock, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		fail("Unable to connect inet socket");
		goto error;
	}

	OK(!ret, "Inet socket %d created connected to %s", inet_sock, ip);

	ret = pthread_create(&th[0], NULL, thread_recv, NULL);
	if (ret < 0) {
		fail("pthread_create thread recv");
		goto error;
	}

	/* Active wait for the thread recv to be ready. */
	while (thread_recv_ready == 0) {
		continue;
	}

	if (thread_recv_ready == -1) {
		goto error;
	}

	ret = pthread_create(&th[1], NULL, thread_send, (void *) &inet_sock);
	if (ret < 0) {
		fail("pthread_create thread send");
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = pthread_join(th[i], &status);
		if (ret < 0) {
			perror("pthread_join");
		}
	}

error:
	if (inet_sock >= 0) {
		close(inet_sock);
	}
	unlink(sockpath);
	return;
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_inet_socket();

    return 0;
}
