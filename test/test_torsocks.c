/***************************************************************************
 *                                                                         *
 * Copyright (c) 2000 Alessandro Iurlano.                                  *
 * Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>                       *
 * Copyright (C) 2011 Robert Hogan <robert@roberthogan.net>                *
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

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef OPENBSD
#include <netinet/in_systm.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#ifndef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifndef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <arpa/nameser.h>
#if defined(__APPLE__) || defined(__darwin__)
#include <arpa/nameser_compat.h>
#endif
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#ifdef OPENBSD
#include <sys/uio.h>
#endif
#include <sys/un.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#ifndef LINUX
#include <sys/queue.h>
#else
#include "queue.h"
#endif

#ifndef PACKETSZ
#define PACKETSZ 512
#endif

static unsigned short csum (unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static int icmp_test()
{

    int sockfd;
    char datagram[400];
    struct sockaddr_in dest;
    struct ip *iphdr=(struct ip *) datagram;
#if defined(OPENBSD) || defined(FREEBSD) ||defined(__APPLE__) || defined(__darwin__)
    struct icmp *icmphdr=(struct icmp *)(iphdr +1);
#else
    struct icmphdr *icmphdr=(struct icmphdr *)(iphdr +1);
#endif
    char *buff=(char *)(icmphdr +1);
    printf("\n----------------icmp() TEST----------------------------\n\n");

    if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0)
    {
        perror("socket");
        exit(1);
    }

    memset(datagram,0,400);
    strcpy(buff,"entzwei");
    dest.sin_family=AF_INET;
    dest.sin_addr.s_addr=inet_addr("192.168.1.33");

    iphdr->ip_v=4;
    iphdr->ip_hl=5;
    iphdr->ip_len=sizeof(datagram);
    iphdr->ip_id=(unsigned char)htonl(54321);
    iphdr->ip_off=0;
    iphdr->ip_ttl=225;
    iphdr->ip_p=1;
    iphdr->ip_sum=0;
    iphdr->ip_tos=0;
    iphdr->ip_src.s_addr=inet_addr("192.168.1.35");
    iphdr->ip_dst.s_addr=dest.sin_addr.s_addr;
    iphdr->ip_sum=csum((unsigned short *)datagram,iphdr->ip_len >> 1);

#if defined(OPENBSD) || defined(FREEBSD) ||defined(__APPLE__) || defined(__darwin__)
    icmphdr->icmp_type=130;
    icmphdr->icmp_code=0;
    icmphdr->icmp_cksum=htons(0xc3b0);
#else
    icmphdr->type=130;
    icmphdr->code=0;
    icmphdr->checksum=htons(0xc3b0);
    icmphdr->un.echo.sequence=0;
    icmphdr->un.echo.id=0;
#endif
    int one=1;
    int *val=&one;
    if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,val,sizeof(one))<0)
        printf("cannot set HDRINCL!\n");


    if(sendto(sockfd,datagram,35,0,(struct sockaddr *)&dest,sizeof(dest))<0)
    {
        perror("sendto");
        exit(1);
    }

    return(0);
}

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

static int res_tests(char *ip, char *test) {
    unsigned char dnsreply[1024];
    unsigned char host[128];
    int ret = 0, i;
    char buf[16];
    struct sockaddr_in addr;

    memset( dnsreply, '\0', sizeof( dnsreply ));

    printf("\n---------------------- %s res_init() TEST----------------------\n\n", test);
    if (res_init() == -1) {
      printf("res_init failed\n");
      return -1;
    }


    addr.sin_family=AF_INET;
    addr.sin_port=htons(53);
    addr.sin_addr.s_addr=inet_addr(ip);

    for (i = 0; i < _res.nscount; i++)
        memcpy(&_res.nsaddr_list[i], &addr, sizeof(struct sockaddr_in));

    inet_ntop(AF_INET, &_res.nsaddr_list[0].sin_addr.s_addr, buf, sizeof(buf));
    printf("nameserver for test: %s\n", buf);

    /* Modifying _res directly doesn't work, so we have to use res_n* where available.
       See: http://sourceware.org/ml/libc-help/2009-11/msg00013.html */
    printf("\n---------------------- %s res_query() TEST----------------------\n\n", test);
    snprintf((char *)host, 127, "www.google.com");
#if !defined(OPENBSD) && !defined(__APPLE__) && !defined(__darwin__)
    ret = res_nquery(&_res, (char *) host, C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
#else
    ret = res_query((char *) host, C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
#endif
    printf("return code: %i\n", ret);

    printf("\n---------------------- %s res_search() TEST----------------------\n\n", test);
    memset( dnsreply, '\0', sizeof( dnsreply ));
#if !defined(OPENBSD) && !defined(__APPLE__) && !defined(__darwin__)
    ret = res_nsearch(&_res, (char *) host, C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
#else
    ret = res_search((char *) host, C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
#endif
    printf("return code: %i\n", ret);

    printf("\n--------------- %s res_querydomain() TEST----------------------\n\n", test);
    memset( dnsreply, '\0', sizeof( dnsreply ));
#if !defined(OPENBSD) && !defined(__APPLE__) && !defined(__darwin__)
    ret = res_nquerydomain(&_res,  "www.google.com", "google.com", C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
#else
    ret = res_querydomain("www.google.com", "google.com", C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
#endif
    printf("return code: %i\n", ret);

    printf("\n---------------------- %s res_send() TEST----------------------\n\n", test);
    memset( dnsreply, '\0', sizeof( dnsreply ));
#if !defined(OPENBSD) && !defined(__APPLE__) && !defined(__darwin__)
    ret = res_nsend(&_res,  host, 32, dnsreply, sizeof( dnsreply ));
#else
    ret = res_send(host, 32, dnsreply, sizeof( dnsreply ));
#endif
printf("return code: %i\n", ret);

    return ret;
}

static int res_internet_tests() {
    char *ip = "8.8.8.8";
    char *test = "internet";
    return res_tests(ip, test);
}

static int res_local_tests() {
    char *ip = "192.168.1.1";
    char *test = "local";
    return res_tests(ip, test);
}

static int udp_test() {
    struct sockaddr_in addr;
    char testtext[]="This message should be sent via udp\nThis is row number 2\nAnd then number three\n";
    int sock,ret,wb,flags=0;
    char *ip = "6.6.6.6";

    printf("\n----------------------UDP TEST----------------------\n\n");

    addr.sin_family=AF_INET;
    addr.sin_port=53;
    addr.sin_addr.s_addr=inet_addr(ip);

    sock=socket(AF_INET,SOCK_DGRAM,0);

    struct iovec iov;
    struct msghdr msg;

    iov.iov_base = (void *)testtext;
    iov.iov_len = strlen(testtext);

    msg.msg_name = (struct sockaddr *)&addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    printf("\n----------------------udp sendmsg() TEST-------------------\n\n");
    wb=0;
    ret=sendmsg(sock, &msg, flags);
    printf("sendmsg() returned ret=%d wb=%d\n",ret,wb);

    printf("\n----------------------udp sendto() TEST--------------------\n\n");
    wb=0;
    ret=sendto(sock,testtext,strlen(testtext)+1,wb, (struct sockaddr*)&addr, sizeof(addr));
    ret=sendto(sock,"CiaoCiao",strlen("CiaoCiao")+1,wb, (struct sockaddr*)&addr, sizeof(addr));
    printf("sendto() returned ret=%d wb=%d\n",ret,wb);

    printf("\n----------------------udp connect() TEST-------------------\n\n");
    ret=connect(sock,(struct sockaddr*)&addr,sizeof(addr));
    printf("Connect returned ret=%d\n",ret);

    printf("\n----------------------udp send() TEST----------------------\n\n");
    wb=0;
    ret=send(sock,testtext,strlen(testtext)+1,wb);
    ret=send(sock,"CiaoCiao",strlen("CiaoCiao")+1,wb);
    printf("Note: no interception by torsocks expected as send() requires a socket in a connected state.\n");
    printf("send() returned ret=%d wb=%d\n",ret,wb);

    return 0;
}

static int gethostbyname_test() {
    struct hostent *foo;

    printf("\n----------------------gethostbyname() TEST-----------------\n\n");

    foo=gethostbyname("www.torproject.org");
    if (foo) {
      int i;
      for (i=0; foo->h_addr_list[i]; ++i)
        printf("%s -> %s\n",foo->h_name,inet_ntoa(*(struct in_addr*)foo->h_addr_list[i]));
/*      for (i=0; foo->h_aliases[i]; ++i)
        printf("  also known as %s\n",foo->h_aliases[i]);*/
    }
    return 0;
}

static int gethostbyaddr_test() {
    struct in_addr bar;
    struct hostent *foo;

    printf("\n----------------------gethostbyaddr() TEST-----------------\n\n");

    inet_aton("38.229.70.16", &bar);
    foo=gethostbyaddr(&bar,4,AF_INET);
    if (foo) {
      int i;
      for (i=0; foo->h_addr_list[i]; ++i)
        printf("%s -> %s\n",foo->h_name,inet_ntoa(*(struct in_addr*)foo->h_addr_list[i]));
      for (i=0; foo->h_aliases[i]; ++i)
        printf("  also known as %s\n",foo->h_aliases[i]);
    }
    return 0;
}

static int getaddrinfo_test() {
    struct addrinfo hints;
    struct addrinfo *result;
    int s;

    printf("\n----------------------getaddrinfo() TEST-----------------\n\n");

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    s = getaddrinfo(NULL, "www.torproject.org", &hints, &result);
    if (s != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(s));
    }

    return 0;
}

/* Unavailable in glibc. */
/*
static int getipnodebyname_test() {
    int error;

    printf("\n----------------------getipnodebyname() TEST-----------------\n\n");

    getipnodebyname("www.torproject.org", AF_INET, 0, &error);
    if (error != 0) {
        printf("getipnodebyname error: %i\n", error);
    }

    return 0;
}
*/

static int connect_test(const char *name, const char *ip, int port)
{
    int sock;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port        = htons(port);

    printf("\n---------------------- %s connect() TEST----------------------\n\n", name);

    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        return 1;

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        return 1;

    return 0;
}

static int connect_local_test()
{
    const char *ip = "192.168.1.1";
    const char *name = "local";
    int port = 80;
    return connect_test(name, ip, port);
}

static int connect_internet_test()
{
    const char *ip = "8.8.8.8";
    int port = 53;
    const char *name = "internet";
    return connect_test(name, ip, port);
}

int main() {

    getaddrinfo_test();
    udp_test();
    gethostbyaddr_test();
    gethostbyname_test();
    connect_local_test();
    connect_internet_test();
    res_internet_tests();
    res_local_tests();
    icmp_test();

    return 0;
}
