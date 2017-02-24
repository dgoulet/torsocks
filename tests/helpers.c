/*
 * Copyright (C) 2017 - David Goulet <dgoulet@ev0ke.net>
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

#include <arpa/inet.h>

#include "lib/torsocks.h"

#include "helpers.h"

/* Try to connect to SocksPort localhost:9050 and if we can't skip. This is
 * to avoid to have failing test if no tor daemon is available. Return 1 if
 * true else 0. */
int
helper_is_default_tor_running(void)
{
  int ret, fd;
  struct sockaddr_in sa;

  fd = tsocks_libc_socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    goto end;
  }
  sa.sin_family = AF_INET;
  sa.sin_port = htons(9050);
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ret = tsocks_libc_connect(fd, (const struct sockaddr *) &sa, sizeof(sa));
  close(fd);
  if (ret < 0) {
    goto end;
  }
  return 1;
end:
  return 0;
}
