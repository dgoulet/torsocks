/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2005 Total Information Security Ltd.                    *
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

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "common.h"
#include "dead_pool.h"

int store_pool_entry(dead_pool *pool, char *hostname, struct in_addr *addr);
void get_next_dead_address(dead_pool *pool, uint32_t *result);

static int
do_resolve(const char *hostname, uint32_t sockshost, uint16_t socksport,
           uint32_t *result_addr, const void *addr,
           int version, int reverse, char **result_hostname);

/* Compares the last strlen(s2) characters of s1 with s2.  Returns as for
   strcasecmp. */
static int 
strcasecmpend(const char *s1, const char *s2)
{
   size_t n1 = strlen(s1), n2 = strlen(s2);
   if (n2>n1) /* then they can't be the same; figure out which is bigger */
       return strcasecmp(s1,s2);
   else
       return strncasecmp(s1+(n1-n2), s2, n2);
}

dead_pool *
init_pool(unsigned int pool_size, struct in_addr deadrange_base, 
    struct in_addr deadrange_mask, char *sockshost, uint16_t socksport)
{
    unsigned int i, deadrange_size, deadrange_width;
    int deadrange_bits;
    struct in_addr socks_server;
    dead_pool *newpool = NULL;

    /* Count bits in netmask and determine deadrange width. */
    deadrange_bits = count_netmask_bits(deadrange_mask.s_addr);
    if(deadrange_bits == -1) {
        show_msg(MSGERR, "init_pool: invalid netmask for deadrange\n");
        return NULL;
    } 
    deadrange_width = 32 - deadrange_bits;

    show_msg(MSGDEBUG, "deadrange width is %d bits\n", deadrange_width);

    /* Now work out how many IPs are available in the deadrange and check
       that this number makes sense.  If the deadpool is bigger than the 
       deadrange we shrink the pool. */

    for(i=0, deadrange_size = 1; i < deadrange_width; i++) {
        deadrange_size *= 2;
    }

    if(deadrange_size < pool_size) {
        show_msg(MSGWARN, "tordns cache size was %d, but deadrange size is %d: "
                 "shrinking pool size to %d entries\n", pool_size, 
                 deadrange_size, deadrange_size);
        pool_size = deadrange_size;
    }
    if(pool_size < 1) {
        show_msg(MSGERR, "tordns cache size is 0, disabling tordns\n");
        return NULL;
    }

    /* Allocate space for the dead_pool structure */
    newpool = (dead_pool *) mmap(0, sizeof(dead_pool), 
                   PROT_READ | PROT_WRITE, 
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0); 
    if(!newpool) {
        show_msg(MSGERR, "init_pool: unable to mmap deadpool "
                 "(tried to map %d bytes)\n", sizeof(dead_pool));
        return NULL;
    }

    show_msg(MSGDEBUG, "init_pool: sockshost %s \n", sockshost);

    /* Initialize the dead_pool structure */
#ifdef HAVE_INET_ATON
    inet_aton(sockshost, &socks_server);
#elif defined(HAVE_INET_ADDR)
    socks_server.s_addr = inet_addr(sockshost);
#endif
    newpool->sockshost = ntohl(socks_server.s_addr);
    newpool->socksport = socksport;
    newpool->deadrange_base = ntohl(deadrange_base.s_addr);
    newpool->deadrange_mask = ntohl(deadrange_mask.s_addr);
    newpool->deadrange_size = deadrange_size;
    newpool->write_pos = 0;
    newpool->dead_pos = 0;
    newpool->n_entries = pool_size;

    /* Allocate space for the entries */
    newpool->entries = (pool_ent *) mmap(0, newpool->n_entries * sizeof(pool_ent), 
                            PROT_READ | PROT_WRITE, 
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0); 
    if(!newpool->entries) {
        munmap((void *)newpool, sizeof(dead_pool));
        show_msg(MSGERR, "init_pool: unable to mmap deadpool entries "
                 "(tried to map %d bytes)\n", 
                 newpool->n_entries * sizeof(pool_ent)); 
        return NULL;
    }

    /* Initialize the entries */
    for(i=0; i < newpool->n_entries; i++) {
        newpool->entries[i].ip = -1;
        newpool->entries[i].name[0] = '\0';
    }

    return newpool;
}

int
is_dead_address(dead_pool *pool, uint32_t addr) 
{
    uint32_t haddr = ntohl(addr);
    if(pool == NULL) {
        return 0;
    }
    return (pool->deadrange_base == (haddr & pool->deadrange_mask));
}

void
get_next_dead_address(dead_pool *pool, uint32_t *result)
{
    *result = htonl(pool->deadrange_base + pool->dead_pos++);
    if(pool->dead_pos >= pool->deadrange_size) {
        pool->dead_pos = 0;
    }
}

int
store_pool_entry(dead_pool *pool, char *hostname, struct in_addr *addr)
{
  int position = pool->write_pos;
  int oldpos;
  int rc;
  uint32_t intaddr;
  char *result_hostname;

  show_msg(MSGDEBUG, "store_pool_entry: storing '%s'\n", hostname);
  show_msg(MSGDEBUG, "store_pool_entry: write pos is: %d\n", pool->write_pos);

  /* Check to see if name already exists in pool */
  oldpos = search_pool_for_name(pool, hostname);
  if(oldpos != -1){
      show_msg(MSGDEBUG, "store_pool_entry: not storing (entry exists)\n");
      addr->s_addr = pool->entries[oldpos].ip;
      return oldpos;
  }

  /* If this is a .onion host, then we return a bogus ip from our deadpool, 
     otherwise we try to resolve it and store the 'real' IP */
  if(strcasecmpend(hostname, ".onion") == 0) {
      get_next_dead_address(pool, &pool->entries[position].ip);
  } else {
      rc = do_resolve(hostname, pool->sockshost, pool->socksport, &intaddr, 0,
                  4 /*SOCKS5*/, 0 /*Reverse*/, &result_hostname);

      if(rc != 0) {
          show_msg(MSGWARN, "failed to resolve: %s\n", hostname);
          return -1;
      } 
      if(is_dead_address(pool, intaddr)) {
          show_msg(MSGERR, "resolved %s -> %d (deadpool address) IGNORED\n");
          return -1;
      }
      pool->entries[position].ip = intaddr;
  }

  strncpy(pool->entries[position].name, hostname, 255);
  pool->entries[position].name[255] = '\0';
  pool->write_pos++;
  if(pool->write_pos >= pool->n_entries) {
      pool->write_pos = 0;
  }
  addr->s_addr = pool->entries[position].ip;

  show_msg(MSGDEBUG, "store_pool_entry: stored entry in slot '%d'\n", position);

  return position;
}

int 
search_pool_for_name(dead_pool *pool, const char *name) 
{
  unsigned int i;
  for(i=0; i < pool->n_entries; i++){
    if(strcmp(name, pool->entries[i].name) == 0){
      return i;
    }
  }
  return -1;
}

char *
get_pool_entry(dead_pool *pool, struct in_addr *addr)
{
  unsigned int i;
  uint32_t intaddr = addr->s_addr;

  if(pool == NULL) {
      return NULL;
  }

  show_msg(MSGDEBUG, "get_pool_entry: searching for: %s\n", inet_ntoa(*addr));
  for(i=0; i<pool->n_entries; i++) {
    if(intaddr == pool->entries[i].ip) {
        show_msg(MSGDEBUG, "get_pool_entry: found: %s\n", pool->entries[i].name);
        return pool->entries[i].name;
    }
  }
  show_msg(MSGDEBUG, "get_pool_entry: address not found\n");

  return NULL;
}

static int
build_socks4a_resolve_request(char **out,
                              const char *username,
                              const char *hostname)
{
  size_t len;
  uint16_t port = htons(0);  /* port: 0. */
  uint32_t addr = htonl(0x00000001u); /* addr: 0.0.0.1 */

  len = 8 + strlen(username) + 1 + strlen(hostname) + 1;
  *out = malloc(len);
  (*out)[0] = 4;      /* SOCKS version 4 */
  (*out)[1] = '\xF0'; /* Command: resolve. */

  memcpy((*out)+2, &port, sizeof(port));
  memcpy((*out)+4, &addr, sizeof(addr));
  strcpy((*out)+8, username);
  strcpy((*out)+8+strlen(username)+1, hostname);

  return len;
}

static int
build_socks5_resolve_ptr_request(char **out, const void *_addr)
{
  size_t len;
  const struct in_addr *addr=_addr;

  len = 12;
  *out = malloc(len);
  (*out)[0] = 5;      /* SOCKS version 5 */
  (*out)[1] = '\xF1'; /* Command: reverse resolve.
                         see doc/socks-extensions.txt*/
  (*out)[2] = '\x00'; /* RSV */
  (*out)[3] = '\x01'; /* ATYP: IP V4 address: X'01' */

  set_uint32((*out)+4, addr->s_addr);/*IP*/
  set_uint16((*out)+4+4, 0); /* port */

  return len;
}

#define RESPONSE_LEN 8
#define SOCKS5_LEN 4
#define METHODRESPONSE_LEN 2

static int
parse_socks4a_resolve_response(const char *response, size_t len,
                               uint32_t *addr_out)
{
  uint8_t status;
  uint16_t port;

  if (len < RESPONSE_LEN) {
    show_msg(MSGWARN,"Truncated socks response.\n"); 
    return -1;
  }
  if (((uint8_t)response[0])!=0) { /* version: 0 */
    show_msg(MSGWARN,"Nonzero version in socks response: bad format.\n");
    return -1;
  }
  status = (uint8_t)response[1];

  memcpy(&port, response+2, sizeof(port));
  if (port!=0) { /* port: 0 */
    show_msg(MSGWARN,"Nonzero port in socks response: bad format.\n"); 
    return -1;
  }
  if (status != 90) {
    show_msg(MSGWARN,"Bad status: socks request failed.\n"); 
    return -1;
  }

  memcpy(addr_out, response+4, sizeof(*addr_out));

  return 0;
}

static int
parse_socks5_resolve_ptr_response(int s,const char *response, size_t len,
                               uint32_t *result_addr, char ***result_hostname)
{
    char reply_buf[4];
    int r;

    len=0;
    while (len < SOCKS5_LEN) {
      r = recv(s, reply_buf+len, SOCKS5_LEN-len, 0);
      if (r==0) {
        show_msg(MSGWARN, "do_resolve: EOF while reading SOCKS5 response\n"); 
        return -1;
      }
      if (r<0) {
        show_msg(MSGWARN, "do_resolve: error reading SOCKS5 response\n"); 
        return -1;
      }
      len += r;
    }

    if (reply_buf[0] != 5) {
      show_msg(MSGWARN, "Bad SOCKS5 reply version.");
      return -1;
    }
    if (reply_buf[1] != 0) {
      show_msg(MSGWARN,"Got status response '%u': SOCKS5 request failed.",
               (unsigned)reply_buf[1]);
      return -1;
    }
    if (reply_buf[3] == 1) {
      /* IPv4 address */
      len=0;
      while (len < SOCKS5_LEN) {
        r = recv(s, reply_buf+len, SOCKS5_LEN-len, 0);
        if (r==0) {
          show_msg(MSGWARN, "do_resolve: EOF while reading SOCKS5 response\n"); 
          return -1;
        }
        if (r<0) {
          show_msg(MSGWARN, "do_resolve: error reading address in SOCKS5 response\n"); 
          return -1;
        }
        len += r;
      }
      *result_addr = ntohl(get_uint32(reply_buf));
    } else if (reply_buf[3] == 3) {
      size_t result_len;
      len=0;
      while (len < 1) {
        r = recv(s, reply_buf+len, 1-len, 0);
        if (r==0) {
          show_msg(MSGWARN, "do_resolve: EOF while reading SOCKS5 response\n"); 
          return -1;
        }
        if (r<0) {
          show_msg(MSGWARN, "do_resolve: error reading address length in SOCKS5 response\n"); 
          return -1;
        }
        len += r;
      }
      result_len = *(uint8_t*)(reply_buf);
      **result_hostname = malloc(result_len+1);
      len=0;
      while (len < (int) result_len) {
        r = recv(s, **result_hostname+len, result_len-len, 0);
        if (r==0) {
          show_msg(MSGWARN, "do_resolve: EOF while reading SOCKS5 response\n"); 
          return -1;
        }
        if (r<0) {
          show_msg(MSGWARN, "do_resolve: error reading hostname in SOCKS5 response\n");
          return -1;
        }
        len += r;
      }

      (**result_hostname)[result_len] = '\0';
    }

  return 0;
}

static int
do_resolve(const char *hostname, uint32_t sockshost, uint16_t socksport,
           uint32_t *result_addr, const void *addr,
           int version, int reverse, char **result_hostname)
{
  int s;
  struct sockaddr_in socksaddr;
  char *req, *cp=NULL;
  int r, len, hslen;
  char response_buf[RESPONSE_LEN];
  const char *handshake="\x05\x01\x00";

  show_msg(MSGDEBUG, "do_resolve: resolving %s\n", hostname);

  /* Create SOCKS connection */
  s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s<0) {
    show_msg(MSGWARN, "do_resolve: problem creating socket\n"); 
    return -1;
  }

  /* Connect to SOCKS server */
  memset(&socksaddr, 0, sizeof(socksaddr));
  socksaddr.sin_family = AF_INET;
  socksaddr.sin_port = htons(socksport);
  socksaddr.sin_addr.s_addr = htonl(sockshost);
  if (realconnect(s, (struct sockaddr*)&socksaddr, sizeof(socksaddr))) {
    show_msg(MSGWARN, "do_resolve: error connecting to SOCKS server\n");
    realclose(s);
    return -1;
  }

  /* If a SOCKS5 connection, perform handshake */
  if (version == 5) {
    char method_buf[2];
    hslen=3;
    while (hslen) {
      r = send(s, handshake, hslen, 0);
      if (r<0) {
        show_msg(MSGWARN, "do_resolve: error sending SOCKS5 method list.\n");
        realclose(s);
        return -1;
      }
      hslen -= r;
      handshake += r;
    }

    len = 0;
    while (len < METHODRESPONSE_LEN) {
      r = recv(s, method_buf+len, METHODRESPONSE_LEN-len, 0);
      if (r==0) {
        show_msg(MSGWARN, "do_resolve: EOF while reading SOCKS response\n");
        realclose(s);
        return -1;
      }
      if (r<0) {
        show_msg(MSGWARN, "do_resolve: error reading SOCKS response\n");
        realclose(s);
        return -1;
      }
      len += r;
    }

    if (method_buf[0] != '\x05') {
      show_msg(MSGWARN, "Unrecognized socks version: %u",
              (unsigned)method_buf[0]);
      realclose(s);
      return -1;
    }
    if (method_buf[1] != '\x00') {
      show_msg(MSGWARN, "Unrecognized socks authentication method: %u",
              (unsigned)method_buf[1]);
      realclose(s);
      return -1;
    }
  }

  /* Create SOCKS request */
  if (reverse) {
    if ((len = build_socks5_resolve_ptr_request(&req, addr))<0) {
      show_msg(MSGWARN, "do_resolve: error generating reverse SOCKS request\n");
      realclose(s);
      return -1;
    }
  }else{
    if ((len = build_socks4a_resolve_request(&req, "", hostname))<0) {
      show_msg(MSGWARN, "do_resolve: error generating SOCKS request\n");
      realclose(s);
      return -1;
    }
  }

  /* Send SOCKS request */
  cp = req;
  while (len) {
    r = send(s, cp, len, 0);
    if (r<0) {
      show_msg(MSGWARN, "do_resolve: error sending SOCKS request\n"); 
      free(req);
      realclose(s);
      return -1;
    }
    len -= r;
    cp += r;
  }
  free(req);

  /* Handle SOCKS Response */
  if (reverse) {
    if (parse_socks5_resolve_ptr_response(s, response_buf, RESPONSE_LEN,
                                          result_addr, &result_hostname) < 0){
      show_msg(MSGWARN, "do_resolve: error parsing SOCKS response\n");
      realclose(s);
      return -1;
    }
  }else{
    /* Process SOCKS response */
    len = 0;
    while (len < RESPONSE_LEN) {
      r = recv(s, response_buf+len, RESPONSE_LEN-len, 0);
      if (r==0) {
        show_msg(MSGWARN, "do_resolve: EOF while reading SOCKS response\n");
        realclose(s);
        return -1;
      }
      if (r<0) {
        show_msg(MSGWARN, "do_resolve: error reading SOCKS response\n");
        realclose(s);
        return -1;
      }
      len += r;
    }
    realclose(s);

    /* Parse SOCKS response */
    if (parse_socks4a_resolve_response(response_buf, RESPONSE_LEN, result_addr) < 0){
      show_msg(MSGWARN, "do_resolve: error parsing SOCKS response\n");
      return -1;
    }
  }


  show_msg(MSGDEBUG, "do_resolve: success\n");

  return 0;
}

struct hostent *
our_gethostbyaddr(dead_pool *pool, const void *_addr, socklen_t len, int type)
{
  const struct in_addr *addr=_addr;
  static struct hostent he;
  uint32_t intaddr=0;
  char *result_hostname=NULL;
  int rc=0;
  static char *addrs[2];
  static char *aliases[2];

  rc = do_resolve("", pool->sockshost, pool->socksport, &intaddr, addr,
                  5 /*SOCKS5*/, 1 /*Reverse*/, &result_hostname);


  if(rc != 0) {
      show_msg(MSGWARN, "failed to reverse resolve: %s\n",
               inet_ntoa(*((struct in_addr *)addr)));
      result_hostname=NULL;
      addrs[0] = NULL;
      addrs[1] = NULL;
  }else{
      addrs[0] = (char *)addr;
      addrs[1] = NULL;
  }

  if (result_hostname)
    he.h_name = result_hostname;
  else
    he.h_name = inet_ntoa(*((struct in_addr *)addr));

  aliases[0] = NULL;
  aliases[1] = NULL;

  he.h_aliases = aliases;
  he.h_length    = len;
  he.h_addrtype  = type;
  he.h_addr_list = addrs;

  if (result_hostname)
      show_msg(MSGTEST, "our_gethostbyaddr: resolved '%s' to: '%s'\n",
              inet_ntoa(*((struct in_addr *)he.h_addr)), result_hostname);

  return &he;

}

struct hostent *
our_gethostbyname(dead_pool *pool, const char *name)
{
  int pos;
  static struct in_addr addr;
  static struct hostent he;
  static char *addrs[2];

  show_msg(MSGTEST, "our_gethostbyname: '%s' requested\n", name);

  pos = store_pool_entry(pool,(char *) name, &addr);
  if(pos == -1) {
      h_errno = HOST_NOT_FOUND;
      return NULL;
  }

  addrs[0] = (char *)&addr;
  addrs[1] = NULL;

  he.h_name      = pool->entries[pos].name;
  he.h_aliases   = NULL;
  he.h_length    = 4;
  he.h_addrtype  = AF_INET;
  he.h_addr_list = addrs;

  show_msg(MSGDEBUG, "our_gethostbyname: resolved '%s' to: '%s'\n", 
           name, inet_ntoa(*((struct in_addr *)he.h_addr)));

  return &he;
}

static struct hostent *
alloc_hostent(int af)
{
    struct hostent *he = NULL;
    char **addr_list = NULL;
    void *addr = NULL;
    char **aliases = NULL;

    if(af != AF_INET && af != AF_INET6) {
        return NULL;
    }

    /* Since the memory we allocate here will be free'd by freehostent and
       that function is opaque to us, it's likely that we'll leak a little 
       bit of memory here. */

    he = malloc(sizeof(struct hostent));
    addr_list = malloc(2 * sizeof(char *));
    if(af == AF_INET6) {
        addr = malloc(sizeof(struct in6_addr));
    } else {
        addr = malloc(sizeof(struct in_addr));
    }
    aliases = malloc(sizeof(char *));

    if(he == NULL || addr_list == NULL || addr == NULL || aliases == NULL) {
        if(he)
            free(he);
        if(addr_list)
            free(addr_list);
        if(addr)
            free(addr);
        if(aliases)
            free(aliases);
    }

    he->h_name = NULL;
    he->h_addr_list = addr_list;
    he->h_addr_list[0] = addr;
    he->h_addr_list[1] = NULL;
    he->h_aliases = aliases;
    he->h_aliases[0] = NULL;
    he->h_length = af == AF_INET ? 4 : 16;
    he->h_addrtype = af;

    return he;
}

/* On Linux, there's no freehostent() anymore; we might as well implement
   this ourselves. */

static void
free_hostent(struct hostent *he)
{
    int i;
    if(he->h_name) {
        free(he->h_name);
    }
    if(he->h_aliases) {
        for(i=0; he->h_aliases[i] != NULL; i++) {
            free(he->h_aliases[i]);
        }
        free(he->h_aliases);
    }
    if(he->h_addr_list) {
        free(he->h_addr_list);
    }
    free(he);
}

int
our_getaddrinfo(dead_pool *pool, const char *node, const char *service, 
                void *hints, void *res)
{
    int pos;
    struct in_addr addr;
    char *ipstr;
    int ret;

    /* If "node" looks like a dotted-decimal ip address, then just call 
       the real getaddrinfo; otherwise we'll need to get an address from 
       our pool. */

    /* TODO: work out what to do with AF_INET6 requests */

#ifdef HAVE_INET_ATON
    if(node && inet_aton(node, &addr) == 0 && memcmp(node,"*",1)) {
#elif defined(HAVE_INET_ADDR)
    /* If we're stuck with inet_addr, then getaddrinfo() won't work 
       properly with 255.255.255.255 (= -1).  There's not much we can
       do about this */
    in_addr_t is_valid;
    is_valid = inet_addr(node);
    if(is_valid == -1) {
#endif
        pos = store_pool_entry(pool, (char *) node, &addr);
        if(pos == -1) {
            return EAI_NONAME;
        } else {
            ipstr = strdup(inet_ntoa(addr));
            ret = realgetaddrinfo(ipstr, service, hints, res);
            free(ipstr);
        }
    } else {
        ret = realgetaddrinfo(node, service, hints, res);
    }

    show_msg(MSGTEST, "our_getaddrinfo: '%s' requested\n", service);
    return ret;
}

struct hostent *
our_getipnodebyname(dead_pool *pool, const char *name, int af, int flags, 
                    int *error_num)
{
    int pos;
    struct hostent *he = NULL;
    int want_4in6 = 0;
    char addr_convert_buf[80];
    struct in_addr pool_addr;

    if(af == AF_INET6) {
        /* Caller has requested an AF_INET6 address, and is not prepared to
           accept IPv4-mapped IPV6 addresses. There's nothing we can do to
           service their request. */
#ifdef OPENBSD
        /* OpenBSD doesn't support the AI_V4MAPPED flag, so just return. */
        return NULL;
#else
        if((flags & AI_V4MAPPED) == 0) {
            show_msg(MSGWARN, "getipnodebyname: asked for V6 addresses only, "
                     "but torsocks can't handle that\n");
            *error_num = NO_RECOVERY;
            return NULL;
        } else {
            want_4in6 = 1;
        }
#endif
    }

    pos = store_pool_entry(pool, (char *)name, &pool_addr);
    if(pos == -1) {
        *error_num = HOST_NOT_FOUND;
        return NULL;
    }

    he = alloc_hostent(af);
    if(he == NULL) {
        show_msg(MSGERR, "getipnodebyname: failed to allocate hostent\n");
        *error_num = NO_RECOVERY;
        return NULL;
    }

    if(want_4in6) {
        /* Convert the ipv4 address in *addr to an IPv4 in IPv6 mapped 
           address. TODO: inet_ntoa() is thread-safe on Solaris but might
           not be on other platforms. */
        strcpy(addr_convert_buf, "::FFFF:");
        strcpy(addr_convert_buf+7, inet_ntoa(pool_addr));
        if(inet_pton(AF_INET6, addr_convert_buf, he->h_addr_list[0]) != 1) {
            show_msg(MSGERR, "getipnodebyname: inet_pton() failed!\n");
            free_hostent(he);
            *error_num = NO_RECOVERY;
            return NULL;
        }
    } else {
        ((struct in_addr *) he->h_addr_list[0])->s_addr = pool_addr.s_addr;
    }
    he->h_name = strdup(name);

    return he;
}


