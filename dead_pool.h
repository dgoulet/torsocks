#ifndef _DEAD_POOL_H
#define _DEAD_POOL_H

#include <config.h>

extern int (*realconnect)(CONNECT_SIGNATURE);
extern int (*realclose)(CLOSE_SIGNATURE);
extern int (*realgetaddrinfo)(GETADDRINFO_SIGNATURE);

struct struct_pool_ent {
  unsigned int ip;
  char name[256];
};

typedef struct struct_pool_ent pool_ent;

struct struct_dead_pool {
  pool_ent *entries;            /* Points to array of pool entries */
  unsigned int n_entries;       /* Number of entries in the deadpool */
  unsigned int deadrange_base;  /* Deadrange start IP in host byte order */
  unsigned int deadrange_mask;  /* Deadrange netmask in host byte order */
  unsigned int deadrange_size;  /* Number of IPs in the deadrange */
  unsigned int write_pos;       /* Next position to use in the pool array */
  unsigned int dead_pos;        /* Next 'unused' deadpool IP */
  uint32_t sockshost;     
  uint16_t socksport;
  char pad[2];
};

typedef struct struct_dead_pool dead_pool;

dead_pool *init_pool(unsigned int deadpool_size, struct in_addr deadrange_base, 
    struct in_addr deadrange_mask, char *sockshost, uint16_t socksport);
int is_dead_address(dead_pool *pool, uint32_t addr);
char *get_pool_entry(dead_pool *pool, struct in_addr *addr);
int search_pool_for_name(dead_pool *pool, const char *name);
struct hostent *our_gethostbyname(dead_pool *pool, const char *name);
int our_getaddrinfo(dead_pool *pool, const char *node, const char *service, 
    void *hints, void *res);
struct hostent *our_getipnodebyname(dead_pool *pool, const char *name, 
    int af, int flags, int *error_num);

#endif /* _DEAD_POOL_H */

