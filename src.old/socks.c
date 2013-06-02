/***************************************************************************
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

static int connect_server(struct connreq *conn);
static int send_socks_request(struct connreq *conn);
static int send_socksv4_request(struct connreq *conn);
static int send_socksv5_method(struct connreq *conn);
static int send_socksv5_connect(struct connreq *conn);
static int send_buffer(struct connreq *conn);
static int recv_buffer(struct connreq *conn);
static int read_socksv5_method(struct connreq *conn);
static int read_socksv4_req(struct connreq *conn);
static int read_socksv5_connect(struct connreq *conn);
static int read_socksv5_auth(struct connreq *conn);
static int send_socksv4a_request(struct connreq *conn, const char *onion_host);


dead_pool *pool = NULL;
struct connreq *requests = NULL;

struct connreq *new_socks_request(int sockid, struct sockaddr_in *connaddr,
                                         struct sockaddr_in *serveraddr,
                                         struct serverent *path)
{
    struct connreq *newconn;

    if ((newconn = malloc(sizeof(*newconn))) == NULL) {
        /* Could not malloc, we're stuffed */
        show_msg(MSGERR, "Could not allocate memory for new socks request\n");
        return(NULL);
    }

    /* Add this connection to be proxied to the list */
    memset(newconn, 0x0, sizeof(*newconn));
    newconn->sockid = sockid;
    newconn->state = UNSTARTED;
    newconn->path = path;
    memcpy(&(newconn->connaddr), connaddr, sizeof(newconn->connaddr));
    memcpy(&(newconn->serveraddr), serveraddr, sizeof(newconn->serveraddr));
    newconn->next = requests;
    requests = newconn;

    return(newconn);
}

void kill_socks_request(struct connreq *conn)
{
    struct connreq *connnode;

    if (requests == conn)
        requests = conn->next;
    else {
        for (connnode = requests; connnode != NULL; connnode = connnode->next) {
            if (connnode->next == conn) {
                connnode->next = conn->next;
                break;
            }
        }
    }

    free(conn);
}

struct connreq *find_socks_request(int sockid, int includefinished)
{
    struct connreq *connnode;

    for (connnode = requests; connnode != NULL; connnode = connnode->next) {
        if (connnode->sockid == sockid) {
            if (((connnode->state == FAILED) || (connnode->state == DONE)) &&
                !includefinished)
                break;
            else
                return(connnode);
        }
    }

    return(NULL);
}

int handle_request(struct connreq *conn)
{
    int rc = 0;
    int i = 0;

    show_msg(MSGDEBUG, "Beginning handle loop for socket %d\n", conn->sockid);

    while ((rc == 0) &&
            (conn->state != FAILED) &&
            (conn->state != DONE) &&
            (i++ < 20)) {
        show_msg(MSGDEBUG, "In request handle loop for socket %d, "
                           "current state of request is %d\n", conn->sockid,
                           conn->state);
        switch(conn->state) {
          case UNSTARTED:
          case CONNECTING:
              rc = connect_server(conn);
              break;
          case CONNECTED:
              rc = send_socks_request(conn);
              break;
          case SENDING:
              rc = send_buffer(conn);
              break;
          case RECEIVING:
              rc = recv_buffer(conn);
              break;
          case SENTV4REQ:
              show_msg(MSGDEBUG, "Receiving reply to SOCKS V4 connect request\n");
              conn->datalen = sizeof(struct sockrep);
              conn->datadone = 0;
              conn->state = RECEIVING;
              conn->nextstate = GOTV4REQ;
              break;
          case GOTV4REQ:
              rc = read_socksv4_req(conn);
              break;
          case SENTV5METHOD:
              show_msg(MSGDEBUG, "Receiving reply to SOCKS V5 method negotiation\n");
              conn->datalen = 2;
              conn->datadone = 0;
              conn->state = RECEIVING;
              conn->nextstate = GOTV5METHOD;
              break;
          case GOTV5METHOD:
              rc = read_socksv5_method(conn);
              break;
          case SENTV5AUTH:
              show_msg(MSGDEBUG, "Receiving reply to SOCKS V5 authentication negotiation\n");
              conn->datalen = 2;
              conn->datadone = 0;
              conn->state = RECEIVING;
              conn->nextstate = GOTV5AUTH;
              break;
          case GOTV5AUTH:
              rc = read_socksv5_auth(conn);
              break;
          case SENTV5CONNECT:
              show_msg(MSGDEBUG, "Receiving reply to SOCKS V5 connect request\n");
              conn->datalen = 10;
              conn->datadone = 0;
              conn->state = RECEIVING;
              conn->nextstate = GOTV5CONNECT;
              break;
          case GOTV5CONNECT:
              rc = read_socksv5_connect(conn);
              break;
        }
        conn->err = errno;
    }

    if (i == 20)
        show_msg(MSGERR, "Ooops, state loop while handling request %d\n",
                conn->sockid);

    show_msg(MSGDEBUG, "Handle loop completed for socket %d in state %d, "
                       "returning %d\n", conn->sockid, conn->state, rc);
    return(rc);
}

static int connect_server(struct connreq *conn)
{
    int rc;

    /* Connect this socket to the socks server */
    show_msg(MSGDEBUG, "Connecting to %s port %d\n",
             inet_ntoa(conn->serveraddr.sin_addr), ntohs(conn->serveraddr.sin_port));

    rc = realconnect(conn->sockid, (CONNECT_SOCKARG) &(conn->serveraddr),
                     sizeof(conn->serveraddr));

    show_msg(MSGDEBUG, "Connect returned %d, errno is %d\n", rc, errno);
    if (rc && errno == EISCONN) {
        rc = 0;
        show_msg(MSGDEBUG, "Socket %d already connected to SOCKS server\n", conn->sockid);
        conn->state = CONNECTED;
    } else if (rc) {
        if (errno != EINPROGRESS) {
            show_msg(MSGERR, "Error %d attempting to connect to SOCKS "
                             "server (%s)\n", errno, strerror(errno));
            conn->state = FAILED;
        } else {
            show_msg(MSGDEBUG, "Connection in progress\n");
            conn->state = CONNECTING;
        }
    } else {
        show_msg(MSGDEBUG, "Socket %d connected to SOCKS server\n", conn->sockid);
        conn->state = CONNECTED;
    }

    return((rc ? errno : 0));
}

static int send_socks_request(struct connreq *conn)
{
    int rc = 0;

    if (conn->path->type == 4) {
        char *name = get_pool_entry(pool, &(conn->connaddr.sin_addr));
        if(name != NULL)
            rc = send_socksv4a_request(conn,name);
        else
            rc = send_socksv4_request(conn);
    } else
        rc = send_socksv5_method(conn);
    return(rc);
}

static int send_socksv4a_request(struct connreq *conn,const char *onion_host)
{
    struct passwd *user;
    struct sockreq *thisreq;
    int endOfUser;
    /* Determine the current username */
    user = getpwuid(getuid());

    thisreq = (struct sockreq *) conn->buffer;
    endOfUser=sizeof(struct sockreq) +
    (user == NULL ? 0 : strlen(user->pw_name)) + 1;

    /* Check the buffer has enough space for the request  */
    /* and the user name                                  */
    conn->datalen = endOfUser+
                    (onion_host == NULL ? 0 : strlen(onion_host)) + 1;
    if (sizeof(conn->buffer) < conn->datalen) {
        show_msg(MSGERR, "The SOCKS username is too long");
        conn->state = FAILED;
        return(ECONNREFUSED);
    }

    /* Create the request */
    thisreq->version = 4;
    thisreq->command = 1;
    thisreq->dstport = conn->connaddr.sin_port;
    thisreq->dstip   = htonl(1);

    /* Copy the username */
    strcpy((char *) thisreq + sizeof(struct sockreq),
          (user == NULL ? "" : user->pw_name));

    /* Copy the onion host */
    strcpy((char *) thisreq + endOfUser,
          (onion_host == NULL ? "" : onion_host));

    conn->datadone = 0;
    conn->state = SENDING;
    conn->nextstate = SENTV4REQ;

    return(0);
}

static int send_socksv4_request(struct connreq *conn)
{
    struct passwd *user;
    struct sockreq *thisreq;

    /* Determine the current username */
    user = getpwuid(getuid());

    thisreq = (struct sockreq *) conn->buffer;

    /* Check the buffer has enough space for the request  */
    /* and the user name                                  */
    conn->datalen = sizeof(struct sockreq) +
                    (user == NULL ? 0 : strlen(user->pw_name)) + 1;
    if (sizeof(conn->buffer) < conn->datalen) {
        show_msg(MSGERR, "The SOCKS username is too long");
        conn->state = FAILED;
        return(ECONNREFUSED);
    }

    /* Create the request */
    thisreq->version = 4;
    thisreq->command = 1;
    thisreq->dstport = conn->connaddr.sin_port;
    thisreq->dstip   = conn->connaddr.sin_addr.s_addr;

    /* Copy the username */
    strcpy((char *) thisreq + sizeof(struct sockreq),
            (user == NULL ? "" : user->pw_name));

    conn->datadone = 0;
    conn->state = SENDING;
    conn->nextstate = SENTV4REQ;

    return(0);
}

static int send_socksv5_method(struct connreq *conn)
{
    char verstring[] = { 0x05,    /* Version 5 SOCKS */
                          0x02,    /* No. Methods     */
                          0x00,    /* Null Auth       */
                          0x02 };  /* User/Pass Auth  */

    show_msg(MSGDEBUG, "Constructing V5 method negotiation\n");
    conn->state = SENDING;
    conn->nextstate = SENTV5METHOD;
    memcpy(conn->buffer, verstring, sizeof(verstring));
    conn->datalen = sizeof(verstring);
    conn->datadone = 0;

    return(0);
}

static int send_socksv5_connect(struct connreq *conn)
{
    int namelen = 0;
    char *name = NULL;
    char constring[] = { 0x05,    /* Version 5 SOCKS */
                          0x01,    /* Connect request */
                          0x00,    /* Reserved        */
                          0x01 };  /* IP Version 4    */

    show_msg(MSGDEBUG, "Constructing V5 connect request\n");
    conn->datadone = 0;
    conn->state = SENDING;
    conn->nextstate = SENTV5CONNECT;
    memcpy(conn->buffer, constring, sizeof(constring));
    conn->datalen = sizeof(constring);

    show_msg(MSGDEBUG, "send_socksv5_connect: looking for: %s\n",
              inet_ntoa(conn->connaddr.sin_addr));

    name = get_pool_entry(pool, &(conn->connaddr.sin_addr));
    if(name != NULL) {
        namelen = strlen(name);
        if(namelen > 255)  /* "Can't happen" */
            name = NULL;
    }
    if(name != NULL) {
        show_msg(MSGDEBUG, "send_socksv5_connect: found it!\n");
        /* Substitute the domain name from the pool into the SOCKS request. */
        conn->buffer[3] = 0x03;  /* Change the ATYP field */
        conn->buffer[4] = namelen;  /* Length of name */
        conn->datalen++;
        memcpy(&conn->buffer[conn->datalen], name, namelen);
        conn->datalen += namelen;
    } else {
        show_msg(MSGDEBUG, "send_socksv5_connect: ip address not found\n");
        /* Use the raw IP address */
        memcpy(&conn->buffer[conn->datalen], &(conn->connaddr.sin_addr.s_addr),
                sizeof(conn->connaddr.sin_addr.s_addr));
        conn->datalen += sizeof(conn->connaddr.sin_addr.s_addr);
    }
    memcpy(&conn->buffer[conn->datalen], &(conn->connaddr.sin_port),
          sizeof(conn->connaddr.sin_port));
    conn->datalen += sizeof(conn->connaddr.sin_port);

    return(0);
}

static int send_buffer(struct connreq *conn)
{
    int rc = 0;

    show_msg(MSGDEBUG, "Writing to server (sending %d bytes)\n", conn->datalen);
    while ((rc == 0) && (conn->datadone != conn->datalen)) {
        rc = send(conn->sockid, conn->buffer + conn->datadone,
                  conn->datalen - conn->datadone, 0);
        if (rc > 0) {
            conn->datadone += rc;
            rc = 0;
        } else {
            if (errno != EWOULDBLOCK)
                show_msg(MSGDEBUG, "Write failed, %s\n", strerror(errno));
            rc = errno;
        }
    }

    if (conn->datadone == conn->datalen)
        conn->state = conn->nextstate;

    show_msg(MSGDEBUG, "Sent %d bytes of %d bytes in buffer, return code is %d\n",
              conn->datadone, conn->datalen, rc);
    return(rc);
}

static int recv_buffer(struct connreq *conn)
{
    int rc = 0;

    show_msg(MSGDEBUG, "Reading from server (expecting %d bytes)\n", conn->datalen);
    while ((rc == 0) && (conn->datadone != conn->datalen)) {
          rc = recv(conn->sockid, conn->buffer + conn->datadone,
                    conn->datalen - conn->datadone, 0);
          if (rc > 0) {
              conn->datadone += rc;
              rc = 0;
          } else if (rc == 0) {
              show_msg(MSGDEBUG, "Peer has shutdown but we only read %d of %d bytes.\n",
                  conn->datadone, conn->datalen);
              rc = ENOTCONN; /* ENOTCONN seems like the most fitting error message */
          } else {
              if (errno != EWOULDBLOCK)
                  show_msg(MSGDEBUG, "Read failed, %s\n", strerror(errno));
              rc = errno;
          }
    }

    if (conn->datadone == conn->datalen)
        conn->state = conn->nextstate;

    show_msg(MSGDEBUG, "Received %d bytes of %d bytes expected, return code is %d\n",
             conn->datadone, conn->datalen, rc);
    return(rc);
}

static int read_socksv5_method(struct connreq *conn)
{
    struct passwd *nixuser;
    char *uname, *upass;

    /* See if we offered an acceptable method */
    if (conn->buffer[1] == '\xff') {
        show_msg(MSGERR, "SOCKS V5 server refused authentication methods\n");
        conn->state = FAILED;
        return(ECONNREFUSED);
    }

    /* If the socks server chose username/password authentication */
    /* (method 2) then do that                                    */
    if ((unsigned short int) conn->buffer[1] == 2) {
        show_msg(MSGDEBUG, "SOCKS V5 server chose username/password authentication\n");

        /* Determine the current *nix username */
        nixuser = getpwuid(getuid());

        if (((uname = conn->path->defuser) == NULL) &&
          ((uname = getenv("TORSOCKS_USERNAME")) == NULL) &&
            ((uname = (nixuser == NULL ? NULL : nixuser->pw_name)) == NULL)) {
            show_msg(MSGERR, "Could not get SOCKS username from "
                    "local passwd file, torsocks.conf "
                    "or $TORSOCKS_USERNAME to authenticate "
                    "with");
            conn->state = FAILED;
            return(ECONNREFUSED);
        }

        if (((upass = getenv("TORSOCKS_PASSWORD")) == NULL) &&
          ((upass = conn->path->defpass) == NULL)) {
            show_msg(MSGERR, "Need a password in torsocks.conf or "
                    "$TORSOCKS_PASSWORD to authenticate with");
            conn->state = FAILED;
            return(ECONNREFUSED);
        }

        /* Check that the username / pass specified will */
        /* fit into the buffer                */
        if ((3 + strlen(uname) + strlen(upass)) >= sizeof(conn->buffer)) {
            show_msg(MSGERR, "The supplied socks username or "
                    "password is too long");
            conn->state = FAILED;
            return(ECONNREFUSED);
        }

        conn->datalen = 0;
        conn->buffer[conn->datalen] = '\x01';
        conn->datalen++;
        conn->buffer[conn->datalen] = (int8_t) strlen(uname);
        conn->datalen++;
        memcpy(&(conn->buffer[conn->datalen]), uname, strlen(uname));
        conn->datalen = conn->datalen + strlen(uname);
        conn->buffer[conn->datalen] = (int8_t) strlen(upass);
        conn->datalen++;
        memcpy(&(conn->buffer[conn->datalen]), upass, strlen(upass));
        conn->datalen = conn->datalen + strlen(upass);

        conn->state = SENDING;
        conn->nextstate = SENTV5AUTH;
        conn->datadone = 0;
    } else
        return(send_socksv5_connect(conn));

    return(0);
}

static int read_socksv5_auth(struct connreq *conn)
{

    if (conn->buffer[1] != '\x00') {
        show_msg(MSGERR, "SOCKS authentication failed, check username and password\n");
        conn->state = FAILED;
        return(ECONNREFUSED);
    }

    /* Ok, we authenticated ok, send the connection request */
    return(send_socksv5_connect(conn));
}

static int read_socksv5_connect(struct connreq *conn)
{

    /* See if the connection succeeded */
    if (conn->buffer[1] != '\x00') {
        show_msg(MSGERR, "SOCKS V5 connect failed: ");
        conn->state = FAILED;
        switch ((int8_t) conn->buffer[1]) {
            case 1:
                show_msg(MSGERR, "General SOCKS server failure\n");
                return(ECONNABORTED);
            case 2:
                show_msg(MSGERR, "Connection denied by rule\n");
                return(ECONNABORTED);
            case 3:
                show_msg(MSGERR, "Network unreachable\n");
                return(ENETUNREACH);
            case 4:
                show_msg(MSGERR, "Host unreachable\n");
                return(EHOSTUNREACH);
            case 5:
                show_msg(MSGERR, "Connection refused\n");
                return(ECONNREFUSED);
            case 6:
                show_msg(MSGERR, "TTL Expired\n");
                return(ETIMEDOUT);
            case 7:
                show_msg(MSGERR, "Command not supported\n");
                return(ECONNABORTED);
            case 8:
                show_msg(MSGERR, "Address type not supported\n");
                return(ECONNABORTED);
            default:
                show_msg(MSGERR, "Unknown error\n");
                return(ECONNABORTED);
        }
    }
    conn->state = DONE;

    return(0);
}

static int read_socksv4_req(struct connreq *conn)
{
    struct sockrep *thisrep;

    thisrep = (struct sockrep *) conn->buffer;

    if (thisrep->result != 90) {
        show_msg(MSGERR, "SOCKS V4 connect rejected:\n");
        conn->state = FAILED;
        switch(thisrep->result) {
          case 91:
              show_msg(MSGERR, "SOCKS server refused connection\n");
              return(ECONNREFUSED);
          case 92:
              show_msg(MSGERR, "SOCKS server refused connection "
                    "because of failed connect to identd "
                    "on this machine\n");
              return(ECONNREFUSED);
          case 93:
              show_msg(MSGERR, "SOCKS server refused connection "
                    "because identd and this library "
                    "reported different user-ids\n");
              return(ECONNREFUSED);
          default:
              show_msg(MSGERR, "Unknown reason\n");
              return(ECONNREFUSED);
        }
    }
    conn->state = DONE;

    return(0);
}
