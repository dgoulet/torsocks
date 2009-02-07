/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#include <stdio.h>

#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/types.h>


#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <syslog.h>
#include <pthread.h>

#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

#ifndef LINUX
#include <sys/queue.h>
#else
#include "queue.h"
#endif

#ifndef PACKETSZ
#define PACKETSZ 512
#endif

static char *txtquery(const char *domain, unsigned int *ttl)
{
    unsigned char answer[PACKETSZ], *answend, *pt;
    char *txt, host[128];
    int len, type, qtype;
    unsigned int cttl, size, txtlen = 0;


    *ttl = 0;
    if(res_init() < 0) {
        printf("^res_init failed\n");
        return NULL;
    }

    printf("*Querying %s\n", domain);

    memset(answer, 0, PACKETSZ);
    qtype = T_TXT;
    if((len = res_query(domain, C_IN, qtype, answer, PACKETSZ)) < 0 || len > PACKETSZ) {
        /*  The DNS server in the SpeedTouch Alcatel 510 modem can't
         *  handle a TXT-query, but it can resolve an ANY-query to a
         *  TXT-record, so we try an ANY-query now.  The thing we try
         *  to resolve normally only has a TXT-record anyway.
         */
        memset(answer, 0, PACKETSZ);
        qtype=T_ANY;
        if((len = res_query(domain, C_IN, qtype, answer, PACKETSZ)) < 0) {
            printf("^Can't query %s\n", domain);
            return NULL;
        }
    }

    answend = answer + len;
    pt = answer + sizeof(HEADER);

    if((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
        printf("^dn_expand failed\n");
        return NULL;
    }

    pt += len;
    if(pt > answend-4) {
        printf("^Bad (too short) DNS reply\n");
        return NULL;
    }

    GETSHORT(type, pt);
    if(type != qtype) {
        printf("^Broken DNS reply.\n");
        return NULL;
    }

    pt += INT16SZ; /* class */
    size = 0;
    do { /* recurse through CNAME rr's */
        pt += size;
        if((len = dn_expand(answer, answend, pt, host, sizeof(host))) < 0) {
            printf("^second dn_expand failed\n");
            return NULL;
        }
        printf("^Host: %s\n", host);
        pt += len;
        if(pt > answend-10) {
            printf("^Bad (too short) DNS reply\n");
            return NULL;
        }
        GETSHORT(type, pt);
        pt += INT16SZ; /* class */
        GETLONG(cttl, pt);
        GETSHORT(size, pt);
        if(pt + size < answer || pt + size > answend) {
            printf("^DNS rr overflow\n");
            return NULL;
        }
    } while(type == T_CNAME);

    if(type != T_TXT) {
        printf("^Not a TXT record\n");
        return NULL;
    }

    if(!size || (txtlen = *pt) >= size || !txtlen) {
        printf("^Broken TXT record (txtlen = %d, size = %d)\n", txtlen, size);
        return NULL;
    }

    if(!(txt = (char *) malloc(txtlen + 1)))
        return NULL;

    memcpy(txt, pt+1, txtlen);
    txt[txtlen] = 0;
    *ttl = cttl;

    return txt;
}


//gcc -fPIC  -g -O2 -Wall -I. -o resinit resinit.c -lc -lresolv
int main() {
  unsigned char dnsreply[1024];
  unsigned char host[128];
  char *dnsrep;
  int ret = 0;
  unsigned int ttl=0;

  memset( dnsreply, '\0', sizeof( dnsreply ));
//   if (res_init() == -1)
//   {
//     printf("res_init failed\n");
//     return -1;
//   }

  snprintf((char *)host, 127, "www.google.com");
  dnsrep = txtquery((const char *)host, &ttl);
  printf("RES_QUERY results: %s.", dnsrep);
  printf("return code: %i\n", ret);
  
  snprintf((char *)host, 127, "www.google.com");
  ret = res_query( (char *) host, C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
  printf("RES_QUERY results: %s.", dnsreply);
  printf("return code: %i\n", ret);
  
  memset( dnsreply, '\0', sizeof( dnsreply ));
  ret = res_search( (char *) host, C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
  printf("RES_SEARCH results: %s.", dnsreply);
  printf("return code: %i\n", ret);
  
  memset( dnsreply, '\0', sizeof( dnsreply ));
  ret = res_querydomain( "www.google.com", "google.com", C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
  printf("RES_QUERYDOMAIN results: %s.", dnsreply);
  printf("return code: %i\n", ret);

  memset( dnsreply, '\0', sizeof( dnsreply ));
  ret = res_send( host, 32, dnsreply, sizeof( dnsreply ));
  printf("RES_SEND results: %s.", dnsreply);
  printf("return code: %i\n", ret);
  
  return ret;
}


