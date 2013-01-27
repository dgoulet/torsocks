/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2010 Alex Rosenberg <alex@ohmantics.net>                *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

/* Mac OS X 10.6 forces any function named "select" to be named "_select$1050"
 * in the output to the assembler. We need to patch select as well, so this
 * isolated code exists without tripping over the Darwin header that causes the
 * probkem.
 */

#if defined(__APPLE__) || defined(__darwin__)

#include <AvailabilityMacros.h>

#if defined(MAC_OS_X_VERSION_10_6)

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include "common.h"

#define SELECT_SIGNATURE int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout
#define SELECT_ARGNAMES n, readfds, writefds, exceptfds, timeout

/* forward declare opaque structures instead of bringing in real Darwin decls. */
typedef struct fd_set fd_set;
struct timeval;

int (*realselect)(SELECT_SIGNATURE);
int torsocks_select_guts(SELECT_SIGNATURE, int (*original_select)(SELECT_SIGNATURE));

int select(SELECT_SIGNATURE) {
  if (!realselect) {
    torsocks_find_library("select", MSGERR, realselect);
  }
  return torsocks_select_guts(SELECT_ARGNAMES, realselect);
}

#endif /* 10.6 */
#endif /* darwin */
