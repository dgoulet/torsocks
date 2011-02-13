/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2010 Alex Rosenberg <alex@ohmantics.net>                *
 *   Copyright (C) 2011 Robert Hogan <robert@roberthogan.net>              *
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

#undef FUNC
#undef FUNCD
#undef FUND32
#undef FUNCD64

#ifdef SUPPORT_RES_API
#define RES_FUNC    FUNC
#define RES_FUNCD   FUNCD
#define RES_FUNCD32 FUNCD32
#define RES_FUNCD64 FUNCD64
#else
#define RES_FUNC    EMPTY_FUNC
#define RES_FUNCD   EMPTY_FUNC
#define RES_FUNCD32 EMPTY_FUNC
#define RES_FUNCD64 EMPTY_FUNC
#endif /* SUPPORT_RES_API */

#define DNS_FUNC    FUNC
#define DNS_FUNCD   FUNCD
#define DNS_FUNCD32 FUNCD32
#define DNS_FUNCD64 FUNCD64

#define EMPTY_FUNC(e,r,s,n,b,m)

#if defined(__APPLE__) || defined(__darwin__)
#ifndef DARWIN_EXPANSION
#define DARWIN_EXPANSION                  PATCH_TABLE_EXPANSION
#endif /* DARWIN_EXPANSION */
#define FUNCD(e,r,s,n,b,m)                DARWIN_EXPANSION(e,r,s,n,b,m)
#if (__LP64__)
#define FUNCD32(e,r,s,n,b,m)              EMPTY_FUNC(e,r,s,n,b,m)
#define FUNCD64(e,r,s,n,b,m)              DARWIN_EXPANSION(e,r,s,n,b,m)
/* This tests if we're building with 10.6 or later headers, not
   if we're running on 10.6. We'd rather do the latter. */
#ifdef MAC_OS_X_VERSION_10_6
#define FUNCD64_106(e,r,s,n,b,m)          DARWIN_EXPANSION(e,r,s,n,b,m)
#else
#define FUNCD64_106(e,r,s,n,b,m)          EMPTY_FUNC(e,r,s,n,b,m)
#endif /* MAC_OS_X_VERSION_10_6 */
#else
#define FUNCD32(e,r,s,n,b,m)              DARWIN_EXPANSION(e,r,s,n,b,m)
#define FUNCD64(e,r,s,n,b,m)              EMPTY_FUNC(e,r,s,n,b,m)
#define FUNCD64_106(e,r,s,n,b,m)          EMPTY_FUNC(e,r,s,n,b,m)
#endif /* (__LP64__) */
#else
#define FUNCD(e,r,s,n,b,m)                EMPTY_FUNC(e,r,s,n,b,m)
#define FUNCD32(e,r,s,n,b,m)              EMPTY_FUNC(e,r,s,n,b,m)
#define FUNCD64(e,r,s,n,b,m)              EMPTY_FUNC(e,r,s,n,b,m)
#define FUNCD64_106(e,r,s,n,b,m)          EMPTY_FUNC(e,r,s,n,b,m)
#endif /* defined(__APPLE__) || defined(__darwin__) */
#define FUNC(e,r,s,n,b,m)                 PATCH_TABLE_EXPANSION(e,r,s,n,b,m)

/*           dlsym   return type         SIG/ARGS            C name                         base name            asm name    */
/* res_init takes void, so we do that one manually. */
/*RES_FUNC  (ERR,    int,                RES_INIT_,          res_init,                      res_init,            "res_init") */
RES_FUNC    (ERR,    int,                RES_QUERY_,         res_query,                     res_query,           "res_query")
RES_FUNC    (ERR,    int,                RES_SEARCH_,        res_search,                    res_search,          "res_search")
#if defined(__APPLE__) || defined(__darwin__)
RES_FUNC    (ERR,    int,                RES_SEND_,          res_send,                      res_send,            "res_send")
#else
/* It is a bit of a mystery why this is required on Linux. See http://code.google.com/p/torsocks/issues/detail?id=3 */
RES_FUNC    (ERR,    int,                RES_SEND_,          res_send,                      res_send,            "__res_send")
#endif
RES_FUNC    (ERR,    int,                RES_QUERYDOMAIN_,   res_querydomain,               res_querydomain,     "res_querydomain")

DNS_FUNC    (ERR,    struct hostent *,   GETHOSTBYNAME_,     gethostbyname,                 gethostbyname,       "gethostbyname")
DNS_FUNC    (ERR,    struct hostent *,   GETHOSTBYADDR_,     gethostbyaddr,                 gethostbyaddr,       "gethostbyaddr")
DNS_FUNC    (ERR,    int,                GETADDRINFO_,       getaddrinfo,                   getaddrinfo,         "getaddrinfo")
/* getipnodebyname is deprecated so do not report an error if it is not available.*/
DNS_FUNC    (WARN,    struct hostent *,  GETIPNODEBYNAME_,   getipnodebyname,               getipnodebyname,     "getipnodebyname")

DNS_FUNC    (ERR,    ssize_t,            SENDTO_,            sendto,                        sendto,              "sendto")
DNS_FUNCD32 (ERR,    ssize_t,            SENDTO_,            sendto_unix2003,               sendto,              "sendto$UNIX2003")
DNS_FUNCD32 (ERR,    ssize_t,            SENDTO_,            sendto_nocancel_unix2003,      sendto,              "sendto$NOCANCEL$UNIX2003")
DNS_FUNCD64 (ERR,    ssize_t,            SENDTO_,            sendto_nocancel,               sendto,              "sendto$NOCANCEL")

DNS_FUNC    (ERR,    ssize_t,            SENDMSG_,           sendmsg,                       sendmsg,             "sendmsg")
DNS_FUNCD32 (ERR,    ssize_t,            SENDMSG_,           sendmsg_unix2003,              sendmsg,             "sendmsg$UNIX2003")
DNS_FUNCD32 (ERR,    ssize_t,            SENDMSG_,           sendmsg_nocancel_unix2003,     sendmsg,             "sendmsg$NOCANCEL$UNIX2003")
DNS_FUNCD64 (ERR,    ssize_t,            SENDMSG_,           sendmsg_nocancel,              sendmsg,             "sendmsg$NOCANCEL")

FUNC        (ERR,    int,                CONNECT_,           connect,                       connect,             "connect")
FUNCD32     (ERR,    int,                CONNECT_,           connect_unix2003,              connect,             "connect$UNIX2003")
FUNCD32     (ERR,    int,                CONNECT_,           connect_nocancel_unix2003,     connect,             "connect$NOCANCEL$UNIX2003")
FUNCD64     (ERR,    int,                CONNECT_,           connect_nocancel,              connect,             "connect$NOCANCEL")

#if !(defined(__APPLE__) || defined(__darwin__) && defined(MAX_OS_X_VERSION_10_6))
/* see darwin_warts.c */
FUNC        (ERR,    int,                SELECT_,            select,                        select,              "select")
#endif
FUNCD       (ERR,    int,                SELECT_,            select_darwinextsn,            select,              "select$DARWIN_EXTSN")
FUNCD       (ERR,    int,                SELECT_,            select_darwinextsn_nocancel,   select,              "select$DARWIN_EXTSN$NOCANCEL")
FUNCD32     (ERR,    int,                SELECT_,            select_unix2003,               select,              "select$UNIX2003")
FUNCD32     (ERR,    int,                SELECT_,            select_nocancel_unix2003,      select,              "select$NOCANCEL$UNIX2003")
FUNCD64     (ERR,    int,                SELECT_,            select_nocancel,               select,              "select$NOCANCEL")
FUNCD64_106 (ERR,    int,                SELECT_,            select_1050,                   select,              "select$1050")

FUNC        (ERR,    int,                POLL_,              poll,                          poll,                "poll")
FUNCD32     (ERR,    int,                POLL_,              poll_unix2003,                 poll,                "poll$UNIX2003")
FUNCD32     (ERR,    int,                POLL_,              poll_nocancel_unix2003,        poll,                "poll$NOCANCEL$UNIX2003")
FUNCD64     (ERR,    int,                POLL_,              poll_nocancel,                 poll,                "poll$NOCANCEL")

FUNC        (ERR,    int,                CLOSE_,             close,                         close,               "close")
FUNCD32     (ERR,    int,                CLOSE_,             close_unix2003,                close,               "close$UNIX2003")
FUNCD32     (ERR,    int,                CLOSE_,             close_nocancel_unix2003,       close,               "close$NOCANCEL$UNIX2003")
FUNCD64     (ERR,    int,                CLOSE_,             close_nocancel,                close,               "close$NOCANCEL")

FUNC        (ERR,    int,                GETPEERNAME_,       getpeername,                   getpeername,         "getpeername")
FUNCD32     (ERR,    int,                GETPEERNAME_,       getpeername_unix2003,          getpeername,         "getpeername$UNIX2003")
