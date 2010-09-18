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
#include <dlfcn.h>
#include "common.h"

#define LOAD_ERROR(s,l) { \
    char *error; \
    error = dlerror(); \
    show_msg(l, "The symbol %s() was not found in any shared " \
                     "library. The error reported was: %s!\n", s, \
                     (error)?error:"not found"); \
    dlerror(); \
    }

#define SELECT_SIGNATURE int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout
#define SELECT_ARGNAMES n, readfds, writefds, exceptfds, timeout

/* forward declare opaque structures instead of bringing in real Darwin decls. */
typedef struct fd_set fd_set;
struct timeval;

int (*realselect)(SELECT_SIGNATURE);
int tsocks_select_guts(SELECT_SIGNATURE, int (*original_select)(SELECT_SIGNATURE));

int select(SELECT_SIGNATURE) {
  if (!realselect) {
	dlerror();
	if ((realselect = dlsym(RTLD_NEXT, "select")) == NULL)
	  LOAD_ERROR("select", MSGERR);
  }
  return tsocks_select_guts(SELECT_ARGNAMES, realselect);
}

#endif /* 10.6 */
#endif /* darwin */
