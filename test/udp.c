/*
 * OSSO - A Micro Kernel OS
 * Copyright (c) 2000 Alessandro Iurlano.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

/******************************* O S S O ***********************************
 * file : $Source: /home/robert/Development/torsockstosvn/torsocks-cvsbackup/torsocks/test/udp.c,v $
 * Description: UDP protocol testing program.
 ***************************************************************************

 ***************************************************************************
 * $Id: udp.c,v 1.1 2008-06-23 19:38:34 hoganrobert Exp $
 ***************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

//gcc -fPIC  -g -O2 -Wall -I. -o udp udp.c -lc

struct sockaddr_in addr;
char testtext[]="This message should be sent via udp\nThis is row number 2\nAnd then number three\n";


int main(int argc, char *argv[]) {
  int sock,ret,wb,flags=0;

  printf("\n----------------------UDP TEST----------------------\n\n");

  addr.sin_family=AF_INET;
  addr.sin_port=53;
  addr.sin_addr.s_addr=159|(134<<8)|(237<<16)|(6<<24);

  sock=socket(AF_INET,SOCK_DGRAM,0);

  printf("socket returned %d\n",sock);

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

  wb=0;
  ret=sendmsg(sock, &msg, flags);
  printf("sendmsg() returned ret=%d wb=%d\n",ret,wb);

  wb=0;
  ret=sendto(sock,testtext,strlen(testtext)+1,wb, (struct sockaddr*)&addr, sizeof(addr));
  ret=sendto(sock,"CiaoCiao",strlen("CiaoCiao")+1,wb, (struct sockaddr*)&addr, sizeof(addr));
  printf("sendto() returned ret=%d wb=%d\n",ret,wb);

  ret=connect(sock,(struct sockaddr*)&addr,sizeof(addr));
  printf("Connect returned ret=%d\n",ret);
  wb=0;
  ret=send(sock,testtext,strlen(testtext)+1,wb);
  ret=send(sock,"CiaoCiao",strlen("CiaoCiao")+1,wb);
  printf("send() returned ret=%d wb=%d\n",ret,wb);


  return 0;
}
