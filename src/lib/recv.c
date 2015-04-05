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
#include <stdlib.h>

#include <common/log.h>

#include "torsocks.h"

/* recvmsg(2) */
TSOCKS_LIBC_DECL(recvmsg, LIBC_RECVMSG_RET_TYPE, LIBC_RECVMSG_SIG)

/*
 * This is the maximum hardcoded amount of fd that is possible to pass through
 * a Unix socket in the Linux kernel. On FreeBSD for instance it's MLEN which
 * is defined to MSIZE (256) minus the msg header size thus way below this
 * Linux limit. Such a shame there is no way to dynamically get that value or
 * get it in an exposed ABI...
 */
#define SCM_MAX_FD  253

/*
 * Close all fds in the given array of size count.
 */
static void close_fds(int *fds, size_t count)
{
	int i;

	for (i = 0; i < count; i++) {
		tsocks_libc_close(fds[i]);
	}
}

/*
 * Torsocks call for recvmsg(2)
 *
 * We only hijack this call to handle the FD passing between process on Unix
 * socket. If an INET/INET6 socket is recevied, we stop everything because at
 * that point we can't guarantee traffic going through Tor.
 *
 * Note that we don't rely on the given "msg" structure since it's controlled
 * by the user and might not have been zeroed thus containing wrong values for
 * ancillary data. Thus, we are going to expect SCM_MAX_FD and see what we can
 * get from that if any.
 */
LIBC_RECVMSG_RET_TYPE tsocks_recvmsg(LIBC_RECVMSG_SIG)
{
	socklen_t addrlen;
	ssize_t ret = 0;
	char dummy, recv_fd[CMSG_SPACE(SCM_MAX_FD)];
	struct iovec iov[1];
	struct cmsghdr *cmsg;
	struct msghdr msg_hdr;
	struct sockaddr addr;

	/* Don't bother if the socket family is NOT Unix. */
	addrlen = sizeof(addr);
	ret = getsockname(sockfd, &addr, &addrlen);
	if (ret < 0) {
		DBG("[recvmsg] Fail getsockname() on sock %d", sockfd);
		errno = EBADF;
		goto error;
	}
	if (addr.sa_family != AF_UNIX) {
		goto libc;
	}

	memset(&msg_hdr, 0, sizeof(msg_hdr));

	/* Prepare to receive the structures */
	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg_hdr.msg_iov = iov;
	msg_hdr.msg_iovlen = 1;
	msg_hdr.msg_control = recv_fd;
	msg_hdr.msg_controllen = sizeof(recv_fd);

	do {
		/* Just peek the data to inspect the payload for fd. */
		ret = tsocks_libc_recvmsg(sockfd, &msg_hdr, MSG_PEEK);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		/* Use the current errno set by the call above. */
		goto error;
	}
	cmsg = CMSG_FIRSTHDR(&msg_hdr);
	if (!cmsg) {
		/* No control message header, safe to pass to libc. */
		goto libc;
	}
	if (msg_hdr.msg_flags & MSG_CTRUNC) {
		/*
		 * This means there are actually *more* data in the control thus
		 * exceeding somehow our hard limit of SCM_MAX_FD. In that case, return
		 * an error since we can't guarantee anything for socket passing
		 */
		errno = EMSGSIZE;
		goto error;
	}

	/*
	 * Detecting FD passing, the next snippet of code will check if we get a
	 * inet/inet6 socket. If so, we are going to close the received socket,
	 * wipe clean the cmsg payload and return an unauthorized access code.
	 */
	if (cmsg->cmsg_type == SCM_RIGHTS || cmsg->cmsg_level == SOL_SOCKET) {
		/*
		 * The kernel control that len value and there is a hard limit so no
		 * chance here of having a crazy high value that could exhaust the
		 * stack memory.
		 */
		size_t sizeof_fds = (cmsg->cmsg_len - sizeof(*cmsg)) / sizeof(int);
		int i, fds[sizeof_fds];

		memcpy(&fds, CMSG_DATA(cmsg), sizeof(fds));

		/*
		 * For each received fds, we will inspect them to see if there is an
		 * inet socket in there and if so, we have to stop, close everything to
		 * avoid fd leak and return an error.
		 */
		for (i = 0; i < sizeof_fds; i++) {
			struct sockaddr addr;
			socklen_t addrlen = sizeof(addr);

			memset(&addr, 0, addrlen);

			/* Get socket protocol family. */
			ret = getsockname(fds[i], &addr, &addrlen);
			if (ret < 0) {
				/* Either a bad fd or not a socket. */
				continue;
			}

			if (addr.sa_family == AF_INET || addr.sa_family == AF_INET6) {
				DBG("[recvmsg] Inet socket passing detected. Denying it.");
				/* We found socket, close everything and return error. */
				close_fds(fds, sizeof_fds);
				/*
				 * The recv(2) man page does *not* mention that errno value
				 * however it's acceptable because Linux LSM can return this
				 * code if the access is denied in the application by a
				 * security module. We are basically simulating this here.
				 */
				errno = EACCES;
				ret = -1;
				goto error;
			}
		}
	}

	/* At this point, NO socket was detected, continue to the libc safely. */

libc:
	return tsocks_libc_recvmsg(LIBC_RECVMSG_ARGS);

error:
	return ret;
}

/*
 * Libc hijacked symbol recvmsg(2).
 */
LIBC_RECVMSG_DECL
{
	if (!tsocks_libc_recvmsg) {
		tsocks_initialize();
		tsocks_libc_recvmsg = tsocks_find_libc_symbol(LIBC_RECVMSG_NAME_STR,
				TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_recvmsg(LIBC_RECVMSG_ARGS);
}
