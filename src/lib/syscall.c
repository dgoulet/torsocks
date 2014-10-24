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
#include <stdarg.h>
#include <sys/mman.h>

#include <common/log.h>

#include "torsocks.h"

/* syscall(2) */
TSOCKS_LIBC_DECL(syscall, LIBC_SYSCALL_RET_TYPE, LIBC_SYSCALL_SIG)

/*
 * Handle close syscall to be called with tsocks call.
 */
static LIBC_CLOSE_RET_TYPE handle_close(va_list args)
{
	int fd;

	fd = va_arg(args, int);

	return tsocks_close(fd);
}

/*
 * Handle socket syscall to go through Tor.
 */
static LIBC_SOCKET_RET_TYPE handle_socket(va_list args)
{
	int domain, type, protocol;

	domain = va_arg(args, int);
	type = va_arg(args, int);
	protocol = va_arg(args, int);

	return tsocks_socket(domain, type, protocol);
}

/*
 * Handle connect syscall to go through Tor.
 */
static LIBC_CONNECT_RET_TYPE handle_connect(va_list args)
{
	int sockfd;
	const struct sockaddr *addr;
	socklen_t addrlen;

	sockfd = va_arg(args, int);
	addr = va_arg(args, const struct sockaddr *);
	addrlen = va_arg(args, socklen_t);

	return tsocks_connect(sockfd, addr, addrlen);
}

/*
 * Handle accept(2) syscall to go through Tor.
 */
static LIBC_ACCEPT_RET_TYPE handle_accept(va_list args)
{
	int sockfd;
	struct sockaddr *addr;
	socklen_t addrlen;

	sockfd = va_arg(args, __typeof__(sockfd));
	addr = va_arg(args, __typeof__(addr));
	addrlen = va_arg(args, __typeof__(addrlen));

	return tsocks_accept(sockfd, addr, &addrlen);
}

#if (defined(__linux__) || defined(__darwin__) || (defined(__FreeBSD_kernel__) && defined(__i386__)))
/*
 * Handle mmap(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_mmap(va_list args)
{
	void *addr;
	size_t len;
	int prot, flags, fd;
	off_t offset;

	addr = va_arg(args, __typeof__(addr));
	len = va_arg(args, __typeof__(len));
	prot = va_arg(args, __typeof__(prot));
	flags = va_arg(args, __typeof__(flags));
	fd = va_arg(args, __typeof__(fd));
	offset = va_arg(args, __typeof__(offset));

	return (LIBC_SYSCALL_RET_TYPE) mmap(addr, len, prot, flags, fd, offset);
}
#endif /* __linux__, __darwin__ */

/*
 * Handle munmap(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_munmap(va_list args)
{
	void *addr;
	size_t len;

	addr = va_arg(args, __typeof__(addr));
	len = va_arg(args, __typeof__(len));

	return (LIBC_SYSCALL_RET_TYPE) munmap(addr, len);
}

/*
 * Handle getpeername(2) syscall.
 */
static LIBC_GETPEERNAME_RET_TYPE handle_getpeername(va_list args)
{
	int sockfd;
	struct sockaddr *addr;
	socklen_t *addrlen;

	sockfd = va_arg(args, __typeof__(sockfd));
	addr = va_arg(args, __typeof__(addr));
	addrlen = va_arg(args, __typeof__(addrlen));

	return tsocks_getpeername(sockfd, addr, addrlen);
}

/*
 * Handle listen(2) syscall.
 */
static LIBC_LISTEN_RET_TYPE handle_listen(va_list args)
{
	int sockfd, backlog;

	sockfd = va_arg(args, __typeof__(sockfd));
	backlog = va_arg(args, __typeof__(backlog));

	return tsocks_listen(sockfd, backlog);
}

/*
 * Handle recvmsg(2) syscall.
 */
static LIBC_RECVMSG_RET_TYPE handle_recvmsg(va_list args)
{
	int sockfd, flags;
	struct msghdr *msg;

	sockfd = va_arg(args, __typeof__(sockfd));
	msg = va_arg(args, __typeof__(msg));
	flags = va_arg(args, __typeof__(flags));

	return tsocks_recvmsg(sockfd, msg, flags);
}

/*
 * Torsocks call for syscall(2)
 */
LIBC_SYSCALL_RET_TYPE tsocks_syscall(long int number, va_list args)
{
	LIBC_SYSCALL_RET_TYPE ret;

	switch (number) {
	case TSOCKS_NR_SOCKET:
		ret = handle_socket(args);
		break;
	case TSOCKS_NR_CONNECT:
		ret = handle_connect(args);
		break;
	case TSOCKS_NR_CLOSE:
		ret = handle_close(args);
		break;
	case TSOCKS_NR_MMAP:
#if (defined(__NetBSD__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) && defined(__x86_64)
		/*
		 * On an 64 bit *BSD system, __syscall(2) should be used for mmap().
		 * This is NOT suppose to happen but for protection we deny that call.
		 */
		ret = -1;
		errno = ENOSYS;
#else
		/*
		 * The mmap/munmap syscall are handled here for a very specific case so
		 * buckle up here for the explanation :).
		 *
		 * Considering an application that handles its own memory using a
		 * malloc(2) hook for instance *AND* mmap() is called with syscall(),
		 * we have to route the call to the libc in order to complete the
		 * syscall() symbol lookup.
		 *
		 * The lookup process of the libdl (using dlsym(3)) calls at some point
		 * malloc for a temporary buffer so we end up in this torsocks wrapper
		 * when mmap() is called to create a new memory region for the
		 * application (remember the malloc hook). When getting here, the libc
		 * syscall() symbol is NOT yet populated because we are in the lookup
		 * code path. For this, we directly call mmap/munmap using the libc so
		 * the lookup can be completed.
		 *
		 * This crazy situation is present in Mozilla Firefox which handles its
		 * own memory using mmap() called by syscall(). Same for munmap().
		 */
		ret = handle_mmap(args);
#endif /* __NetBSD__, __FreeBSD__, __FreeBSD_kernel__, __x86_64 */
		break;
	case TSOCKS_NR_MUNMAP:
		ret = handle_munmap(args);
		break;
	case TSOCKS_NR_ACCEPT:
		ret = handle_accept(args);
		break;
	case TSOCKS_NR_GETPEERNAME:
		ret = handle_getpeername(args);
		break;
	case TSOCKS_NR_LISTEN:
		ret = handle_listen(args);
		break;
	case TSOCKS_NR_RECVMSG:
		ret = handle_recvmsg(args);
		break;
	default:
		/* Safe to call the libc syscall function. */
		ret = tsocks_libc_syscall(number, args);
		break;
	}

	return ret;
}

/*
 * Libc hijacked symbol syscall(2).
 */
LIBC_SYSCALL_DECL
{
	LIBC_SYSCALL_RET_TYPE ret;
	va_list args;

	if (!tsocks_libc_syscall) {
		tsocks_libc_syscall= tsocks_find_libc_symbol(
				LIBC_SYSCALL_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	va_start(args, number);
	ret = tsocks_syscall(number, args);
	va_end(args);

	return ret;
}

/* Only used for *BSD systems. */
#if (defined(__NetBSD__) || defined(__FreeBSD__))

/* __syscall(2) */
TSOCKS_LIBC_DECL(__syscall, LIBC___SYSCALL_RET_TYPE, LIBC___SYSCALL_SIG)

/*
 * Handle *BSD mmap(2) syscall.
 */
static LIBC___SYSCALL_RET_TYPE handle_bsd_mmap(va_list args)
{
	void *addr;
	size_t len;
	int prot, flags, fd;
	off_t offset;

	addr = va_arg(args, __typeof__(addr));
	len = va_arg(args, __typeof__(len));
	prot = va_arg(args, __typeof__(prot));
	flags = va_arg(args, __typeof__(flags));
	fd = va_arg(args, __typeof__(fd));
	offset = va_arg(args, __typeof__(offset));

	return (LIBC___SYSCALL_RET_TYPE) mmap(addr, len, prot, flags, fd, offset);
}

LIBC___SYSCALL_RET_TYPE tsocks___syscall(quad_t number, va_list args)
{
	LIBC_SYSCALL_RET_TYPE ret;

	switch (number) {
	case TSOCKS_NR_MMAP:
		/*
		 * Please see the mmap comment in the syscall() function to understand
		 * why mmap is being hijacked.
		 */
		ret = handle_bsd_mmap(args);
		break;
	default:
		/*
		 * Deny call since we have no idea if this call can leak or not data
		 * off the Tor network.
		 */
		WARN("[syscall] Unsupported __syscall number %ld. Denying the call",
				number);
		ret = -1;
		errno = ENOSYS;
		break;
	}

	return ret;
}

LIBC___SYSCALL_DECL
{
	LIBC___SYSCALL_RET_TYPE ret;
	va_list args;

	va_start(args, number);
	ret = tsocks___syscall(number, args);
	va_end(args);

	return ret;
}

#endif /* __NetBSD__, __FreeBSD__ */
