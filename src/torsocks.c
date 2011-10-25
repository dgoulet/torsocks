/***************************************************************************
 *                                                                         *
 *                                                                         *
 *   Copyright (C) 2000-2008 Shaun Clowes <delius@progsoc.org>             *
 *   Copyright (C) 2008-2011 Robert Hogan <robert@roberthogan.net>         *
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

/* PreProcessor Defines */
#include <config.h>

/*Defining _NONSTD_SOURCE causes library and kernel calls to behave as closely
to Mac OS X 10.3's library and kernel calls as possible.*/
#if defined(__APPLE__) || defined(__darwin__)
/*
From 'man compat' in OSX:
64-BIT COMPILATION
     When compiling for 64-bit architectures, the __LP64__ macro will be defined to 1, and UNIX conformance
     is always on (the _DARWIN_FEATURE_UNIX_CONFORMANCE macro will also be defined to the SUS conformance
     level).  Defining _NONSTD_SOURCE will cause a compilation error.
*/
#if !defined(__LP64__)
#define _NONSTD_SOURCE 1
#endif
#include <sys/socket.h>
#endif


#ifdef USE_GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Global configuration variables */
const char *torsocks_progname = "libtorsocks";         /* Name used in err msgs    */

/* Header Files */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#if !defined(__APPLE__) && !defined(__darwin__)
#include <sys/socket.h>
#endif
#include <resolv.h>

#include "common.h"
#include "dead_pool.h"
#include "parser.h"
#include "socks.h"

/* Some function names are macroized on Darwin. Allow those names
   to expand accordingly. */
#define EXPAND_GUTS(x) torsocks_##x##_guts
#define EXPAND_GUTS_NAME(x) EXPAND_GUTS(x)

/* Function prototypes for original functions that we patch */
#ifdef SUPPORT_RES_API
int (*realres_init)(void);
#endif
#define PATCH_TABLE_EXPANSION(e,r,s,n,b,m) r (*real##n)(s##SIGNATURE);
#include "expansion_table.h"
#undef PATCH_TABLE_EXPANSION
#undef DARWIN_EXPANSION

static struct parsedfile config;
static int suid = 0;
static char *conffile = NULL;

/* Exported Function Prototypes */
void __attribute__ ((constructor)) torsocks_init(void);

/* Function prototypes for our patches */
#ifdef SUPPORT_RES_API
int res_init(void);
#endif

#define PATCH_TABLE_EXPANSION(e,r,s,n,b,m) r n(s##SIGNATURE);
#define DARWIN_EXPANSION(e,r,s,n,b,m)      r n(s##SIGNATURE) __asm("_" m);
#include "expansion_table.h"
#undef PATCH_TABLE_EXPANSION
#undef DARWIN_EXPANSION

/* Private Function Prototypes */
/* no torsocks_res_init_guts */
#define PATCH_TABLE_EXPANSION(e,r,s,n,b,m) r torsocks_##b##_guts(s##SIGNATURE, r (*original_##b)(s##SIGNATURE));
#include "expansion_table.h"
#undef PATCH_TABLE_EXPANSION


static int get_config();
static int get_environment();
static int deadpool_init(void);

static pthread_mutex_t torsocks_init_mutex = PTHREAD_MUTEX_INITIALIZER;

void torsocks_init(void)
{
#define LOAD_ERROR(s,l) { \
    const char *error; \
    error = dlerror(); \
    show_msg(l, "The symbol %s() was not found in any shared " \
                     "library. The error reported was: %s!\n", s, \
                     (error)?error:"not found"); \
    dlerror(); \
    }
    pthread_mutex_lock(&torsocks_init_mutex);

    show_msg(MSGDEBUG, "In torsocks_init \n");

    get_environment();
    get_config();

#ifdef USE_OLD_DLSYM
    void *lib;
#endif

    /* We could do all our initialization here, but to be honest */
    /* most programs that are run won't use our services, so     */
    /* we do our general initialization on first call            */

    /* Determine the logging level */
    suid = (getuid() != geteuid());

    dlerror();
#ifndef USE_OLD_DLSYM
    #ifdef SUPPORT_RES_API
    if ((realres_init = dlsym(RTLD_NEXT, "res_init")) == NULL)
        LOAD_ERROR("res_init", MSGERR);
    #endif
    #define PATCH_TABLE_EXPANSION(e,r,s,n,b,m)  if ((real##n = dlsym(RTLD_NEXT, m)) == NULL) LOAD_ERROR(m, MSG##e);
    #include "expansion_table.h"
    #undef PATCH_TABLE_EXPANSION
#else
    lib = dlopen(LIBCONNECT, RTLD_LAZY);
    realconnect = dlsym(lib, "connect");
    realselect = dlsym(lib, "select");
    realpoll = dlsym(lib, "poll");
    realgethostbyname = dlsym(lib, "gethostbyname");
    realgethostbyaddr = dlsym(lib, "gethostbyaddr");
    realgetaddrinfo = dlsym(lib, "getaddrinfo");
    realgetipnodebyname = dlsym(lib, "getipnodebyname");
    realsendto = dlsym(lib, "sendto");
    realsendmsg = dlsym(lib, "sendmsg");
    dlclose(lib);
    lib = dlopen(LIBC, RTLD_LAZY);
    realclose = dlsym(lib, "close");
    dlclose(lib);
    #ifdef SUPPORT_RES_API
    lib = dlopen(LIBRESOLV, RTLD_LAZY);
    realres_init = dlsym(lib, "res_init");
    realresquery = dlsym(lib, "res_query");
    realressend = dlsym(lib, "res_send");
    realresquerydomain = dlsym(lib, "res_querydomain");
    realressearch = dlsym(lib, "res_search");
    dlclose(lib);
    #endif
#endif
    /* Unfortunately, we can't do this lazily because otherwise our mmap'd
       area won't be shared across fork()s. */
    if (!deadpool_init()) {
        show_msg(MSGERR, "Fatal error: exiting\n");
        exit(1);
    }

    pthread_mutex_unlock(&torsocks_init_mutex);

    show_msg(MSGDEBUG, "Exit torsocks_init \n");
}

static int get_environment()
{
    static int done = 0;
    int loglevel = MSGERR;
    char *logfile = NULL;
    char *env;

    if (done)
        return(0);

   /* Determine the logging level */
    if ((env = getenv("TORSOCKS_DEBUG")))
        loglevel = atoi(env);
    if (((env = getenv("TORSOCKS_DEBUG_FILE"))) && !suid)
        logfile = env;
    set_log_options(loglevel, logfile, (loglevel == MSGTEST) ? 0 : 1);

    done = 1;

    return(0);
}

static int get_config ()
{
    static int done = 0;

    if (done)
        return(0);

    /* Determine the location of the config file */
#ifdef ALLOW_ENV_CONFIG
    if (!suid)
        conffile = getenv("TORSOCKS_CONF_FILE");
#endif

    /* Read in the config file */
    read_config(conffile, &config);
    if (config.paths)
        show_msg(MSGDEBUG, "First lineno for first path is %d\n", config.paths->lineno);

    done = 1;

    return(0);
}

/* Patch trampoline functions */
/* no torsocks_res_init_guts */
#define PATCH_TABLE_EXPANSION(e,r,s,n,b,m) \
   r n(s##SIGNATURE) { \
     if (!real##n) { \
       dlerror(); \
       if ((real##n = dlsym(RTLD_NEXT, m)) == NULL) \
         LOAD_ERROR(m, MSG##e); \
     } \
     return torsocks_##b##_guts(s##ARGNAMES, real##n); \
   }
#include "expansion_table.h"
#undef PATCH_TABLE_EXPANSION

int torsocks_connect_guts(CONNECT_SIGNATURE, int (*original_connect)(CONNECT_SIGNATURE))
{
    struct sockaddr_in *connaddr;
    struct sockaddr_in peer_address;
    struct sockaddr_in server_address;
    int gotvalidserver = 0, rc;
    socklen_t namelen = sizeof(peer_address);
    int sock_type = -1;
    socklen_t sock_type_len = sizeof(sock_type);
    int res = -1;
    struct serverent *path;
    struct connreq *newconn;

    /* If the real connect doesn't exist, we're stuffed */
    if (original_connect == NULL) {
        show_msg(MSGERR, "Unresolved symbol: connect\n");
        return(-1);
    }

    show_msg(MSGTEST, "Got connection request\n");

    connaddr = (struct sockaddr_in *) __addr;

    /* Get the type of the socket */
    getsockopt(__fd, SOL_SOCKET, SO_TYPE,
            (void *) &sock_type, &sock_type_len);

    show_msg(MSGDEBUG, "sin_family: %i\n", connaddr->sin_family);

    show_msg(MSGDEBUG, "sockopt: %i \n", sock_type);

    /* If the address is local refuse it. We do this because it could
       be a TCP DNS request to a local DNS server.*/
    if (!(is_local(&config, &(connaddr->sin_addr))) &&
        !is_dead_address(pool, connaddr->sin_addr.s_addr)) {
        char buf[16];
        inet_ntop(AF_INET, &(connaddr->sin_addr), buf, sizeof(buf));
        show_msg(MSGERR, "connect: Connection is to a local address (%s), may be a "
                         "TCP DNS request to a local DNS server so have to reject to be safe. "
                         "Please report a bug to http://code.google.com/p/torsocks/issues/entry if "
                         "this is preventing a program from working properly with torsocks.\n", buf);
        return -1;
    }

    /* If this isn't an INET socket we can't  */
    /* handle it, just call the real connect now        */
    if ((connaddr->sin_family != AF_INET)) {
        show_msg(MSGDEBUG, "connect: Connection isn't IPv4, ignoring\n");
        return(original_connect(__fd, __addr, __len));
    }

    /* If this a UDP socket  */
    /* then we refuse it, since it is probably a DNS request      */
    if ((sock_type != SOCK_STREAM)) {
        show_msg(MSGERR, "connect: Connection is a UDP or ICMP stream, may be a "
                           "DNS request or other form of leak: rejecting.\n");
        return -1;
    }

    /* If we haven't initialized yet, do it now */
    get_config();

    /* Are we already handling this connect? */
    if ((newconn = find_socks_request(__fd, 1))) {
        if (memcmp(&newconn->connaddr, connaddr, sizeof(*connaddr))) {
            /* Ok, they're calling connect on a socket that is in our
             * queue but this connect() isn't to the same destination,
             * they're obviously not trying to check the status of
             * they're non blocking connect, they must have close()d
             * the other socket and created a new one which happens
             * to have the same fd as a request we haven't had the chance
             * to delete yet, so we delete it here. */
            show_msg(MSGDEBUG, "Call to connect received on old "
                                "torsocks request for socket %d but to "
                                "new destination, deleting old request\n",
                      newconn->sockid);
            kill_socks_request(newconn);
        } else {
            /* Ok, this call to connect() is to check the status of
             * a current non blocking connect(). */
            if (newconn->state == FAILED) {
                show_msg(MSGDEBUG, "Call to connect received on failed "
                                  "request %d, returning %d\n",
                        newconn->sockid, newconn->err);
                errno = newconn->err;
                rc = -1;
            } else if (newconn->state == DONE) {
                show_msg(MSGERR, "Call to connect received on completed "
                                "request %d\n",
                        newconn->sockid, newconn->err);
                rc = 0;
            } else {
                show_msg(MSGDEBUG, "Call to connect received on current request %d\n",
                        newconn->sockid);
                rc = handle_request(newconn);
                errno = rc;
            }
            if ((newconn->state == FAILED) || (newconn->state == DONE))
                kill_socks_request(newconn);
            return((rc ? -1 : 0));
        }
    }

    /* If the socket is already connected, just call connect  */
    /* and get its standard reply                             */
    if (!getpeername(__fd, (struct sockaddr *) &peer_address, &namelen)) {
        show_msg(MSGDEBUG, "Socket is already connected, defering to "
                          "real connect\n");
        return(original_connect(__fd, __addr, __len));
    }

    show_msg(MSGDEBUG, "Got connection request for socket %d to "
                        "%s\n", __fd, inet_ntoa(connaddr->sin_addr));

    /* Ok, so its not local, we need a path to the net */
    pick_server(&config, &path, &(connaddr->sin_addr), ntohs(connaddr->sin_port));

    show_msg(MSGDEBUG, "Picked server %s for connection\n",
              (path->address ? path->address : "(Not Provided)"));
    if (path->address == NULL) {
        if (path == &(config.defaultserver))
            show_msg(MSGERR, "Connection needs to be made "
                              "via default server but "
                              "the default server has not "
                              "been specified\n");
        else
            show_msg(MSGERR, "Connection needs to be made "
                              "via path specified at line "
                              "%d in configuration file but "
                              "the server has not been "
                              "specified for this path\n",
                              path->lineno);
    } else if ((res = resolve_ip(path->address, 0, 0)) == -1) {
        show_msg(MSGERR, "The SOCKS server (%s) listed in the configuration "
                        "file which needs to be used for this connection "
                        "is invalid\n", path->address);
    } else {
        /* Construct the addr for the socks server */
        server_address.sin_family = AF_INET; /* host byte order */
        server_address.sin_addr.s_addr = res;
        server_address.sin_port = htons(path->port);
        bzero(&(server_address.sin_zero), 8);

        /* Complain if this server isn't on a localnet */
        if (is_local(&config, &server_address.sin_addr)) {
            show_msg(MSGERR, "SOCKS server %s (%s) is not on a local subnet!\n",
                     path->address, inet_ntoa(server_address.sin_addr));
        } else
            gotvalidserver = 1;
    }

    /* If we haven't found a valid server we return connection refused */
    if (!gotvalidserver ||
        !(newconn = new_socks_request(__fd, connaddr, &server_address, path))) {
        errno = ECONNREFUSED;
        return(-1);
    } else {
        /* Now we call the main function to handle the connect. */
        rc = handle_request(newconn);
        /* If the request completed immediately it mustn't have been
        * a non blocking socket, in this case we don't need to know
        * about this socket anymore. */
        if ((newconn->state == FAILED) || (newconn->state == DONE))
            kill_socks_request(newconn);
        errno = rc;
        /* We may get either of these if there are no bytes to read from 
           the non-blocking connection in handle_request(). Since we are 
           wrapping connect() here we can't return EWOULDBLOCK/EAGAIN
           so override it with something the client will accept.*/
        if (errno == EWOULDBLOCK || errno == EAGAIN)
            errno = EINPROGRESS;
        return((rc ? -1 : 0));
    }
}

int torsocks_select_guts(SELECT_SIGNATURE, int (*original_select)(SELECT_SIGNATURE))
{
    int nevents = 0;
    int rc = 0;
    int setevents = 0;
    int monitoring = 0;
    struct connreq *conn, *nextconn;
    fd_set mywritefds, myreadfds, myexceptfds;

    /* If we're not currently managing any requests we can just
     * leave here */
    if (!requests) {
        show_msg(MSGDEBUG, "No requests waiting, calling real select\n");
        return(original_select(n, readfds, writefds, exceptfds, timeout));
    }

    show_msg(MSGTEST, "Intercepted call to select\n");
    show_msg(MSGDEBUG, "Intercepted call to select with %d fds, "
              "0x%08x 0x%08x 0x%08x, timeout %08x\n", n,
              readfds, writefds, exceptfds, timeout);

    for (conn = requests; conn != NULL; conn = conn->next) {
        if ((conn->state == FAILED) || (conn->state == DONE))
            continue;
        conn->selectevents = 0;
        show_msg(MSGDEBUG, "Checking requests for socks enabled socket %d\n",
                 conn->sockid);
        conn->selectevents |= (writefds ? (FD_ISSET(conn->sockid, writefds) ? WRITE : 0) : 0);
        conn->selectevents |= (readfds ? (FD_ISSET(conn->sockid, readfds) ? READ : 0) : 0);
        conn->selectevents |= (exceptfds ? (FD_ISSET(conn->sockid, exceptfds) ? EXCEPT : 0) : 0);
        if (conn->selectevents) {
            show_msg(MSGDEBUG, "Socket %d was set for events\n", conn->sockid);
            monitoring = 1;
        }
    }

    if (!monitoring)
        return(original_select(n, readfds, writefds, exceptfds, timeout));

    /* This is our select loop. In it we repeatedly call select(). We
      * pass select the same fdsets as provided by the caller except we
      * modify the fdsets for the sockets we're managing to get events
      * we're interested in (while negotiating with the socks server). When
      * events we're interested in happen we go off and process the result
      * ourselves, without returning the events to the caller. The loop
      * ends when an event which isn't one we need to handle occurs or
      * the select times out */
    do {
        /* Copy the clients fd events, we'll change them as we wish */
        if (readfds)
            memcpy(&myreadfds, readfds, sizeof(myreadfds));
        else
            FD_ZERO(&myreadfds);
        if (writefds)
            memcpy(&mywritefds, writefds, sizeof(mywritefds));
        else
            FD_ZERO(&mywritefds);
        if (exceptfds)
            memcpy(&myexceptfds, exceptfds, sizeof(myexceptfds));
        else
            FD_ZERO(&myexceptfds);

        /* Now enable our sockets for the events WE want to hear about */
        for (conn = requests; conn != NULL; conn = conn->next) {
            if ((conn->state == FAILED) || (conn->state == DONE) ||
                (conn->selectevents == 0))
                continue;
            /* We always want to know about socket exceptions */
            FD_SET(conn->sockid, &myexceptfds);
            /* If we're waiting for a connect or to be able to send
              * on a socket we want to get write events */
            if ((conn->state == SENDING) || (conn->state == CONNECTING))
                FD_SET(conn->sockid,&mywritefds);
            else
                FD_CLR(conn->sockid,&mywritefds);
            /* If we're waiting to receive data we want to get
              * read events */
            if (conn->state == RECEIVING)
                FD_SET(conn->sockid,&myreadfds);
            else
                FD_CLR(conn->sockid,&myreadfds);
        }

        nevents = original_select(n, &myreadfds, &mywritefds, &myexceptfds, timeout);
        /* If there were no events we must have timed out or had an error */
        if (nevents <= 0)
            break;

        /* Loop through all the sockets we're monitoring and see if
        * any of them have had events */
        for (conn = requests; conn != NULL; conn = nextconn) {
            nextconn = conn->next;
            if ((conn->state == FAILED) || (conn->state == DONE))
                continue;
            show_msg(MSGDEBUG, "Checking socket %d for events\n", conn->sockid);
            /* Clear all the events on the socket (if any), we'll reset
              * any that are necessary later. */
            setevents = 0;
            if (FD_ISSET(conn->sockid, &mywritefds))  {
                nevents--;
                setevents |= WRITE;
                show_msg(MSGDEBUG, "Socket had write event\n");
                FD_CLR(conn->sockid, &mywritefds);
            }
            if (FD_ISSET(conn->sockid, &myreadfds))  {
                nevents--;
                setevents |= READ;
                show_msg(MSGDEBUG, "Socket had write event\n");
                FD_CLR(conn->sockid, &myreadfds);
            }
            if (FD_ISSET(conn->sockid, &myexceptfds))  {
                nevents--;
                setevents |= EXCEPT;
                show_msg(MSGDEBUG, "Socket had except event\n");
                FD_CLR(conn->sockid, &myexceptfds);
            }

            if (!setevents) {
                show_msg(MSGDEBUG, "No events on socket %d\n", conn->sockid);
                continue;
            }

            if (setevents & EXCEPT)
                conn->state = FAILED;
            else
                rc = handle_request(conn);

            /* If the connection hasn't failed or completed there is nothing
              * to report to the client */
            if ((conn->state != FAILED) &&
                (conn->state != DONE))
                continue;

            /* Ok, the connection is completed, for good or for bad. We now
              * hand back the relevant events to the caller. We don't delete the
              * connection though since the caller should call connect() to
              * check the status, we delete it then */

            if (conn->state == FAILED) {
                /* Damn, the connection failed. Whatever the events the socket
                * was selected for we flag */
                if (conn->selectevents & EXCEPT) {
                    FD_SET(conn->sockid, &myexceptfds);
                    nevents++;
                }
                if (conn->selectevents & READ) {
                    FD_SET(conn->sockid, &myreadfds);
                    nevents++;
                }
                if (conn->selectevents & WRITE) {
                    FD_SET(conn->sockid, &mywritefds);
                    nevents++;
                }
                /* We should use setsockopt to set the SO_ERROR errno for this
                * socket, but this isn't allowed for some silly reason which
                * leaves us a bit hamstrung.
                * We don't delete the request so that hopefully we can
                * return the error on the socket if they call connect() on it */
            } else {
                /* The connection is done,  if the client selected for
                * writing we can go ahead and signal that now (since the socket must
                * be ready for writing), otherwise we'll just let the select loop
                * come around again (since we can't flag it for read, we don't know
                * if there is any data to be read and can't be bothered checking) */
                if (conn->selectevents & WRITE) {
                    FD_SET(conn->sockid, &mywritefds);
                    nevents++;
                }
            }
        }
    } while (nevents == 0);

    show_msg(MSGDEBUG, "Finished intercepting select(), %d events\n", nevents);

    /* Now copy our event blocks back to the client blocks */
    if (readfds)
        memcpy(readfds, &myreadfds, sizeof(myreadfds));
    if (writefds)
        memcpy(writefds, &mywritefds, sizeof(mywritefds));
    if (exceptfds)
        memcpy(exceptfds, &myexceptfds, sizeof(myexceptfds));

    return(nevents);
}

int torsocks_poll_guts(POLL_SIGNATURE, int (*original_poll)(POLL_SIGNATURE))
{
    int nevents = 0;
    int rc = 0;
    unsigned int i;
    int setevents = 0;
    int monitoring = 0;
    struct connreq *conn, *nextconn;

    /* If we're not currently managing any requests we can just
      * leave here */
    if (!requests)
        return(original_poll(ufds, nfds, timeout));

    show_msg(MSGTEST, "Intercepted call to poll\n");
    show_msg(MSGDEBUG, "Intercepted call to poll with %d fds, "
              "0x%08x timeout %d\n", nfds, ufds, timeout);

    for (conn = requests; conn != NULL; conn = conn->next)
        conn->selectevents = 0;

    /* Record what events on our sockets the caller was interested
      * in */
    for (i = 0; i < nfds; i++) {
        if (!(conn = find_socks_request(ufds[i].fd, 0)))
            continue;
        show_msg(MSGDEBUG, "Have event checks for socks enabled socket %d\n",
                conn->sockid);
        conn->selectevents = ufds[i].events;
        monitoring = 1;
    }

    if (!monitoring)
        return(original_poll(ufds, nfds, timeout));

    /* This is our poll loop. In it we repeatedly call poll(). We
      * pass select the same event list as provided by the caller except we
      * modify the events for the sockets we're managing to get events
      * we're interested in (while negotiating with the socks server). When
      * events we're interested in happen we go off and process the result
      * ourselves, without returning the events to the caller. The loop
      * ends when an event which isn't one we need to handle occurs or
      * the poll times out */
    do {
        /* Enable our sockets for the events WE want to hear about */
        for (i = 0; i < nfds; i++) {
            if (!(conn = find_socks_request(ufds[i].fd, 0)))
                continue;

            /* We always want to know about socket exceptions but they're
              * always returned (i.e they don't need to be in the list of
              * wanted events to be returned by the kernel */
            ufds[i].events = 0;

            /* If we're waiting for a connect or to be able to send
              * on a socket we want to get write events */
            if ((conn->state == SENDING) || (conn->state == CONNECTING))
                ufds[i].events |= POLLOUT;
            /* If we're waiting to receive data we want to get
              * read events */
            if (conn->state == RECEIVING)
                ufds[i].events |= POLLIN;
        }

        nevents = original_poll(ufds, nfds, timeout);
        /* If there were no events we must have timed out or had an error */
        if (nevents <= 0)
            break;

        /* Loop through all the sockets we're monitoring and see if
        * any of them have had events */
        for (conn = requests; conn != NULL; conn = nextconn) {
            nextconn = conn->next;
            if ((conn->state == FAILED) || (conn->state == DONE))
                continue;

            /* Find the socket in the poll list */
            for (i = 0; ((i < nfds) && (ufds[i].fd != conn->sockid)); i++)
                /* Empty Loop */;
            if (i == nfds)
                continue;

            show_msg(MSGDEBUG, "Checking socket %d for events\n", conn->sockid);

            if (!ufds[i].revents) {
                show_msg(MSGDEBUG, "No events on socket\n");
                continue;
            }

            /* Clear any read or write events on the socket, we'll reset
              * any that are necessary later. */
            setevents = ufds[i].revents;
            if (setevents & POLLIN) {
                show_msg(MSGDEBUG, "Socket had read event\n");
                ufds[i].revents &= ~POLLIN;
                nevents--;
            }
            if (setevents & POLLOUT) {
                show_msg(MSGDEBUG, "Socket had write event\n");
                ufds[i].revents &= ~POLLOUT;
                nevents--;
            }
            if (setevents & (POLLERR | POLLNVAL | POLLHUP))
                show_msg(MSGDEBUG, "Socket had error event\n");

            /* Now handle this event */
            if (setevents & (POLLERR | POLLNVAL | POLLHUP)) {
                conn->state = FAILED;
            } else {
                rc = handle_request(conn);
            }
            /* If the connection hasn't failed or completed there is nothing
              * to report to the client */
            if ((conn->state != FAILED) &&
                (conn->state != DONE))
                continue;

            /* Ok, the connection is completed, for good or for bad. We now
             * hand back the relevant events to the caller. We don't delete the
             * connection though since the caller should call connect() to
             * check the status, we delete it then */

            if (conn->state == FAILED) {
                /* Damn, the connection failed. Just copy back the error events
                 * from the poll call, error events are always valid even if not
                 * requested by the client */
                /* We should use setsockopt to set the SO_ERROR errno for this
                 * socket, but this isn't allowed for some silly reason which
                 * leaves us a bit hamstrung.
                 * We don't delete the request so that hopefully we can
                 * return the error on the socket if they call connect() on it */
            } else {
                /* The connection is done,  if the client polled for
                 * writing we can go ahead and signal that now (since the socket must
                 * be ready for writing), otherwise we'll just let the select loop
                 * come around again (since we can't flag it for read, we don't know
                 * if there is any data to be read and can't be bothered checking) */
                if (conn->selectevents & POLLOUT) {
                  setevents |= POLLOUT;
                  nevents++;
                }
            }
        }
    } while (nevents == 0);

    show_msg(MSGDEBUG, "Finished intercepting poll(), %d events\n", nevents);

    /* Now restore the events polled in each of the blocks */
    for (i = 0; i < nfds; i++) {
        if (!(conn = find_socks_request(ufds[i].fd, 1)))
            continue;
        ufds[i].events = conn->selectevents;
    }

    return(nevents);
}

int torsocks_close_guts(CLOSE_SIGNATURE, int (*original_close)(CLOSE_SIGNATURE))
{
    int rc;
    struct connreq *conn;

    /* If we're not currently managing any requests we can just
      * leave here */
    if (!requests) {
        show_msg(MSGDEBUG, "No requests waiting, calling real close\n");
        return(original_close(fd));
    }

    if (original_close == NULL) {
        show_msg(MSGERR, "Unresolved symbol: close\n");
        return(-1);
    }

    show_msg(MSGTEST, "Got call to close()\n");
    show_msg(MSGDEBUG, "Call to close(%d)\n", fd);

    rc = original_close(fd);

    /* If we have this fd in our request handling list we
    * remove it now */
    if ((conn = find_socks_request(fd, 1))) {
        show_msg(MSGDEBUG, "Call to close() received on file descriptor "
                            "%d which is a connection request of status %d\n",
                 conn->sockid, conn->state);
        kill_socks_request(conn);
    }

    return(rc);
}

/* If we are not done setting up the connection yet, return
 * -1 and ENOTCONN, otherwise call getpeername
 *
 * This is necessary since some applications, when using non-blocking connect,
 * (like ircII) use getpeername() to find out if they are connected already.
 *
 * This results in races sometimes, where the client sends data to the socket
 * before we are done with the socks connection setup.  Another solution would
 * be to intercept send().
 * 
 * This could be extended to actually set the peername to the peer the
 * client application has requested, but not for now.
 *
 * PP, Sat, 27 Mar 2004 11:30:23 +0100
 */

int torsocks_getpeername_guts(GETPEERNAME_SIGNATURE,
                            int (*original_getpeername)(GETPEERNAME_SIGNATURE))
{
    struct connreq *conn;
    int rc;

    if (original_getpeername == NULL) {
        show_msg(MSGERR, "Unresolved symbol: getpeername\n");
        return(-1);
    }

    show_msg(MSGTEST, "Intercepted call to getpeername\n");
    show_msg(MSGDEBUG, "Call to getpeername for fd %d\n", __fd);


    rc = original_getpeername(__fd, __name, __namelen);
    if (rc == -1)
        return rc;

    /* Are we handling this connect? */
    if ((conn = find_socks_request(__fd, 1))) {
        /* While we are at it, we might was well try to do something useful */
        handle_request(conn);

        if (conn->state != DONE) {
            errno = ENOTCONN;
            return(-1);
        }
    }
    return rc;
}

#ifdef SUPPORT_RES_API
int res_init(void)
{
    int rc;

    if (!realres_init && ((realres_init = dlsym(RTLD_NEXT, "res_init")) == NULL))
        LOAD_ERROR("res_init", MSGERR);

    show_msg(MSGTEST, "Got res_init request\n");

    if (realres_init == NULL) {
        show_msg(MSGERR, "Unresolved symbol: res_init\n");
        return(-1);
    }
    /* Call normal res_init */
    rc = realres_init();

    /* Force using TCP protocol for DNS queries */
    _res.options |= RES_USEVC;
    return(rc);
}

int EXPAND_GUTS_NAME(res_query)(RES_QUERY_SIGNATURE, int (*original_res_query)(RES_QUERY_SIGNATURE))
{
    int rc;

    if (!original_res_query && ((original_res_query = dlsym(RTLD_NEXT, "res_query")) == NULL))
        LOAD_ERROR("res_query", MSGERR);

    show_msg(MSGTEST, "Got res_query request\n");

    if (original_res_query == NULL) {
        show_msg(MSGERR, "Unresolved symbol: res_query\n");
        return(-1);
    }

    /* Ensure we force using TCP for DNS queries by calling res_init
       above if it has not already been called.*/
    if (!(_res.options & RES_INIT) || !(_res.options & RES_USEVC))
        res_init();

    /* Call normal res_query */
    rc = original_res_query(dname, class, type, answer, anslen);

    return(rc);
}

int EXPAND_GUTS_NAME(res_querydomain)(RES_QUERYDOMAIN_SIGNATURE, int (*original_res_querydomain)(RES_QUERYDOMAIN_SIGNATURE))
{
    int rc;

    if (!original_res_querydomain &&
        ((original_res_querydomain = dlsym(RTLD_NEXT, "res_querydomain")) == NULL))
        LOAD_ERROR("res_querydoimain", MSGERR);

    show_msg(MSGDEBUG, "Got res_querydomain request\n");

    if (original_res_querydomain == NULL) {
        show_msg(MSGERR, "Unresolved symbol: res_querydomain\n");
        return(-1);
    }

    /* Ensure we force using TCP for DNS queries by calling res_init
       above if it has not already been called.*/
    if (!(_res.options & RES_INIT) || !(_res.options & RES_USEVC))
        res_init();

    /* Call normal res_querydomain */
    rc = original_res_querydomain(name, domain, class, type, answer, anslen);

    return(rc);
}

int EXPAND_GUTS_NAME(res_search)(RES_SEARCH_SIGNATURE, int (*original_res_search)(RES_SEARCH_SIGNATURE))
{
    int rc;

    if (!original_res_search &&
        ((original_res_search = dlsym(RTLD_NEXT, "res_search")) == NULL))
            LOAD_ERROR("res_search", MSGERR);

    show_msg(MSGTEST, "Got res_search request\n");

    if (original_res_search == NULL) {
        show_msg(MSGERR, "Unresolved symbol: res_search\n");
        return(-1);
    }

    /* Ensure we force using TCP for DNS queries by calling res_init
       above if it has not already been called.*/
    if (!(_res.options & RES_INIT) || !(_res.options & RES_USEVC))
        res_init();

    /* Call normal res_search */
    rc = original_res_search(dname, class, type, answer, anslen);

    return(rc);
}

int EXPAND_GUTS_NAME(res_send)(RES_SEND_SIGNATURE, int (*original_res_send)(RES_SEND_SIGNATURE))
{
    int rc;

    if (!original_res_send && ((original_res_send = dlsym(RTLD_NEXT, "res_send")) == NULL))
            LOAD_ERROR("res_send", MSGERR);

    show_msg(MSGTEST, "Got res_send request\n");

    if (original_res_send == NULL) {
        show_msg(MSGERR, "Unresolved symbol: res_send\n");
        return(-1);
    }

    /* Ensure we force using TCP for DNS queries by calling res_init
       above if it has not already been called.*/
    if (!(_res.options & RES_INIT) || !(_res.options & RES_USEVC))
        res_init();

    /* Call normal res_send */
    rc = original_res_send(msg, msglen, answer, anslen);

    return(rc);
}
#endif

static int deadpool_init(void)
{
    if (pool)
        return 1;

    if (!config.tordns_enabled) {
        show_msg(MSGERR, "Tor DNS is disabled. Check your configuration.\n");
        return 0;
    }

    get_environment();
    get_config();
    pool = init_pool(config.tordns_cache_size,
                     config.tordns_deadpool_range->localip,
                     config.tordns_deadpool_range->localnet,
                     config.defaultserver.address,
                     config.defaultserver.port);

    if (!pool) {
        show_msg(MSGERR, "Could not initialize reserved addresses for "
                         ".onion addresses. Torsocks will not work properly.\n");
        return 0;
    }
    return 1;
}

struct hostent *torsocks_gethostbyname_guts(GETHOSTBYNAME_SIGNATURE, struct hostent *(*original_gethostbyname)(GETHOSTBYNAME_SIGNATURE))
{
    if (pool)
        return our_gethostbyname(pool, name);
    return original_gethostbyname(name);
}

struct hostent *torsocks_gethostbyaddr_guts(GETHOSTBYADDR_SIGNATURE, struct hostent *(*original_gethostbyaddr)(GETHOSTBYADDR_SIGNATURE))
{
    if (pool)
        return our_gethostbyaddr(pool, addr, len, type);
    return original_gethostbyaddr(addr, len, type);
}

int torsocks_getaddrinfo_guts(GETADDRINFO_SIGNATURE, int (*original_getaddrinfo)(GETADDRINFO_SIGNATURE))
{
    if (pool)
        return our_getaddrinfo(pool, node, service, hints, res);
    return original_getaddrinfo(node, service, hints, res);
}

struct hostent *torsocks_getipnodebyname_guts(GETIPNODEBYNAME_SIGNATURE, struct hostent *(*original_getipnodebyname)(GETIPNODEBYNAME_SIGNATURE))
{
    if (pool)
        return our_getipnodebyname(pool, name, af, flags, error_num);
    return original_getipnodebyname(name, af, flags, error_num);
}

ssize_t torsocks_sendto_guts(SENDTO_SIGNATURE, ssize_t (*original_sendto)(SENDTO_SIGNATURE))
{
    int sock_type = -1;
    unsigned int sock_type_len = sizeof(sock_type);
    struct sockaddr_in *connaddr;

    /* If the real sendto doesn't exist, we're stuffed */
    if (original_sendto == NULL) {
        show_msg(MSGERR, "Unresolved symbol: sendto\n");
        return(-1);
    }

    show_msg(MSGTEST, "Got sendto request\n");

    /* Get the type of the socket */
    getsockopt(s, SOL_SOCKET, SO_TYPE,
               (void *) &sock_type, &sock_type_len);

    show_msg(MSGDEBUG, "sockopt: %i\n",  sock_type);

    /* If this a UDP socket then we refuse it, since it is probably a DNS
       request */
    if ((sock_type != SOCK_STREAM)) {
        show_msg(MSGERR, "sendto: Connection is a UDP or ICMP stream, may be a "
                           "DNS request or other form of leak: rejecting.\n");
        return -1;
    }

    connaddr = (struct sockaddr_in *) to;

    /* If there is no address in 'to', sendto will only work if we
       already allowed the socket to connect(), so we let it through.
       Likewise if the socket is not an Internet connection. */
    if (connaddr && (connaddr->sin_family != AF_INET)) {
        show_msg(MSGDEBUG, "Connection isn't an Internet socket ignoring\n");
    }

    return (ssize_t) original_sendto(s, buf, len, flags, to, tolen);
}

ssize_t torsocks_sendmsg_guts(SENDMSG_SIGNATURE, ssize_t (*original_sendmsg)(SENDMSG_SIGNATURE))
{
    int sock_type = -1;
    unsigned int sock_type_len = sizeof(sock_type);
    struct sockaddr_in *connaddr;

    /* If the real sendmsg doesn't exist, we're stuffed */
    if (original_sendmsg == NULL) {
        show_msg(MSGERR, "Unresolved symbol: sendmsg\n");
        return(-1);
    }

    show_msg(MSGTEST, "Got sendmsg request\n");

    /* Get the type of the socket */
    getsockopt(s, SOL_SOCKET, SO_TYPE,
               (void *) &sock_type, &sock_type_len);

    show_msg(MSGDEBUG, "sockopt: %i\n",  sock_type);

    if ((sock_type != SOCK_STREAM)) {
        show_msg(MSGERR, "sendmsg: Connection is a UDP or ICMP stream, may be a "
                          "DNS request or other form of leak: rejecting.\n");
        return -1;
    }

    connaddr = (struct sockaddr_in *) msg->msg_name;

    /* If there is no address in msg_name, sendmsg will only work if we
       already allowed the socket to connect(), so we let it through.
       Likewise if the socket is not an Internet connection. */
    if (connaddr && (connaddr->sin_family != AF_INET)) {
        show_msg(MSGDEBUG, "Connection isn't an Internet socket\n");
    }

    return (ssize_t) original_sendmsg(s, msg, flags);
}

