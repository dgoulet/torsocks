/*

    INSPECTSOCKS - Part of the tsocks package
		   This utility can be used to determine the protocol 
		   level of a SOCKS server.

    Copyright (C) 2000 Shaun Clowes 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

/* Global configuration variables */ 
char *progname = "inspectsocks";	   /* Name for error msgs      */
int defaultport	= 1080;			   /* Default SOCKS port       */

/* Header Files */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <common.h>

int send_request(struct sockaddr_in *server, void *req, 
                 int reqlen, void *rep, int replen);

int main(int argc, char *argv[]) {
	char *usage = "Usage: <socks server name/ip> [portno]";
	char req[9];
	char resp[100];
	unsigned short int portno = defaultport;
	int ver = 0;
	int read_bytes;
	struct sockaddr_in server;

	if ((argc < 2) || (argc > 3)) {
		show_msg(MSGERR, "Invalid number of arguments\n");
		show_msg(MSGERR, "%s\n", usage);
		exit(1);
	}

	switch (argc) {
		case 3:
			portno = (unsigned short int)
				 strtol(argv[2], (char **) 0, 10);
			if ((portno == 0) || (errno == EINVAL)) {
				show_msg(MSGERR, "%s\n", usage);
				exit(1);
			}
		case 2:
			if ((server.sin_addr.s_addr = resolve_ip(argv[1], 1,HOSTNAMES))
                            ==  -1) {
				show_msg(MSGERR, "Invalid IP/host specified (%s)\n", argv[1]);
				show_msg(MSGERR, "%s\n", usage);
				exit(1);
			}
	}

	server.sin_family = AF_INET; /* host byte order */
	server.sin_port = htons(portno);     /* short, network byte order */
	bzero(&(server.sin_zero), 8);/* zero the rest of the struct */

	/* Now, we send a SOCKS V5 request which happens to be */
	/* the same size as the smallest possible SOCKS V4     */
	/* request. In this packet we specify we have 7 auth   */
	/* methods but specify them all as NO AUTH.            */
	bzero(req, sizeof(req));
	req[0] = '\x05';
	req[1] = '\x07';
	read_bytes = send_request(&server, req, 
				  sizeof(req), resp, sizeof(resp));
	if (read_bytes > 0) {
		if ((int) resp[0] == 0) {
			ver = 4;
		} else if ((int) resp[0] == 5) {
			ver = 5;
		} 
		if (ver != 0) {
			printf("Reply indicates server is a version "
			       "%d socks server\n", ver);
		} else {
			show_msg(MSGERR, "Invalid SOCKS version reply (%d), "
			       	   "probably not a socks server\n",
				   ver);
		}
		exit(0);
	}	

	/* Hmmm.... disconnected so try a V4 request */
	printf("Server disconnected V5 request, trying V4\n");
	req[0] = '\x04';
	req[1] = '\x01';
	read_bytes = send_request(&server, req, 
				  sizeof(req), resp, sizeof(resp));	
	if (read_bytes > 0) {
		if ((int) resp[0] == 0) {
			ver = 4;
		} 
		if (ver == 4) {
			printf("Reply indicates server is a version "
			       "4 socks server\n");
		} else {
			show_msg(MSGERR, "Invalid SOCKS version reply (%d), "
			       	   "probably not a socks server\n",
				   (int) resp[0]);
		}
		exit(0);
	} else {
		show_msg(MSGERR, "Server disconnected, probably not a "
			   "socks server\n");
	}

	return(0);  
}

int send_request(struct sockaddr_in *server, void *req, 
		 int reqlen, void *rep, int replen) {
	int sock;
	int rc;

	if ((sock = socket(server->sin_family, SOCK_STREAM, 0)) < 0)
	{
		show_msg(MSGERR, "Could not create socket (%s)\n",
			   strerror(errno));
		exit(1);
	}
	
	if (connect(sock, (struct sockaddr *) server,
		    sizeof(struct sockaddr_in)) != -1) {
	} else {
		show_msg(MSGERR, "Connect failed! (%s)\n",
			   strerror(errno));
		exit(1);
	}

	if (send(sock, (void *) req, reqlen,0) < 0) {
		show_msg(MSGERR, "Could not send to server (%s)\n",
			   strerror(errno));
		exit(1);
	}

	/* Now wait for reply */
	if ((rc = recv(sock, (void *) rep, replen, 0)) < 0) {
		show_msg(MSGERR, "Could not read from server\n",
			   strerror(errno));
		exit(1);
	}

	close(sock);

	return(rc);
	
}
