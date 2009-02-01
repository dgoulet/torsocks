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

//gcc -fPIC  -g -O2 -Wall -I. -o resinit resinit.c -lc -lresolv
int main() {
  unsigned char dnsreply[1024];
  unsigned char host[128];
  int ret = 0;

  memset( dnsreply, '\0', sizeof( dnsreply ));
  if (res_init() == -1)
  {
    printf("res_init failed\n");
    return -1;
  }

  snprintf((char *)host, 127, "google.com");
  ret = res_query( (char *) host, C_IN, T_TXT, dnsreply, sizeof( dnsreply ));
  printf("results: %s.", dnsreply);
  printf("return code: %i\n", ret);
  return ret;
}

