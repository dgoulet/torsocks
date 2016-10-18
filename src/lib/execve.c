/*
 * Copyright (C) 2016 - David Goulet <dgoulet@ev0ke.net>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include "torsocks.h"

/* execve(2) */
TSOCKS_LIBC_DECL(execve, LIBC_EXECVE_RET_TYPE, LIBC_EXECVE_SIG)

/*
 * Check the file for setuid or security capabilities. Return 1 if
 * capabilities or suid is set which indicates that LD_PRELOAD will be
 * stripped. If none of those are present, return 0.
 */
int
check_cap_suid(const char *filename)
{
	struct stat perms;

	if (stat(filename, &perms) == 0) {
		if (perms.st_mode & (S_ISUID | S_ISGID)) {
			/* setXuid is enabled, LD_PRELOAD will be stripped */
			return -1;
		}
	}

/* Capabilities as such are just on Linux. */
#ifdef __linux__
#include <sys/xattr.h>
	static const char *sec_cap = "security.capability";
	ssize_t len = getxattr(filename, sec_cap, NULL, 0);
	if (len > 0) {
		/* security capabilities are set, LD_PRELOAD will be stripped */
		return -1;
	}
	/* On failure or a value of zero, either no caps are present or the
	 * filename wasn't found so in both cases, let execve() call handle the
	 * failure if one. */
#endif /* __linux__ */

	return 0;
}

/*
 * execve() is hijacked to avoid executing setuid or setcap binaries which
 * will strip the LD_PRELOAD settings.
 */
LIBC_EXECVE_RET_TYPE tsocks_execve(LIBC_EXECVE_SIG)
{
	if (check_cap_suid(filename) < 0) {
		errno = EPERM;
		return -1;
	}
	return tsocks_libc_execve(filename, argv, envp);
}

/*
 * Libc hijacked symbol execve(2).
 */
LIBC_EXECVE_DECL
{
	if (!tsocks_libc_execve) {
		tsocks_initialize();
	}
	return tsocks_execve(LIBC_EXECVE_ARGS);
}
