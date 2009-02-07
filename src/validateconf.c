/***************************************************************************
 *                                                                         *
 * $Id: validateconf.c,v 1.2 2008-07-06 15:17:35 hoganrobert Exp $                            *
 *                                                                         *
 *   Copyright (C) 2008 by Robert Hogan                                    *
 *   robert@roberthogan.net                                                *
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
 ***************************************************************************
 *                                                                         *
 *   This is a modified version of a source file from the tsocks project.  *
 *   Original copyright notice from tsocks source file follows:            *
 *                                                                         *
 ***************************************************************************/
/*

    VALIDATECONF - Part of the tsocks package
		   This utility can be used to validate the torsocks.conf
		   configuration file

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
const char *progname = "validateconf";	      /* Name for error msgs      */

/* Header Files */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <common.h>
#include <parser.h>

void show_server(struct parsedfile *, struct serverent *, int);
void show_conf(struct parsedfile *config);
void test_host(struct parsedfile *config, char *);

int main(int argc, char *argv[]) {
	const char *usage = "Usage: [-f conf file] [-t hostname/ip[:port]]"; 
	char *filename = NULL;
	char *testhost = NULL;
   struct parsedfile config;
	int i;

	if ((argc > 5) || (((argc - 1) % 2) != 0)) {
		show_msg(MSGERR, "Invalid number of arguments\n");
		show_msg(MSGERR, "%s\n", usage);
		exit(1);
	}

	for (i = 1; i < argc; i = i + 2) {
		if (!strcmp(argv[i], "-f")) {
			filename = argv[(i + 1)];
		} else if (!strcmp(argv[i], "-t")) {
			testhost = argv[(i + 1)];
		} else {
			show_msg(MSGERR, "Unknown option %s\n", argv[i]);
			show_msg(MSGERR, "%s\n", usage);
			exit(1);
		}
	}

	if (!filename) 
		filename = strdup(CONF_FILE);

	printf("Reading configuration file %s...\n", filename);
	if (read_config(filename, &config) == 0)
		printf("... Read complete\n\n");
	else 
		exit(1);

	/* If they specified a test host, test it, otherwise */
	/* dump the configuration                            */
	if (!testhost)
		show_conf(&config);
	else
		test_host(&config, testhost);
	
	return(0);  
}

void test_host(struct parsedfile *config, char *host) { 
	struct in_addr hostaddr;
	struct serverent *path;
   char *hostname, *port;
   char separator;
   unsigned long portno = 0;

   /* See if a port has been specified */
   hostname = strsplit(&separator, &host, ": \t\n");
   if (separator == ':') {
      port = strsplit(NULL, &host, " \t\n");
      if (port) 
         portno = strtol(port, NULL, 0);
   }

	/* First resolve the host to an ip */
	if ((hostaddr.s_addr = resolve_ip(hostname, 0, 1)) == 0) {
		fprintf(stderr, "Error: Cannot resolve %s\n", host);
		return;
	} else {
		printf("Finding path for %s...\n", inet_ntoa(hostaddr));
      if (!(is_local(config, &(hostaddr)))) {
         printf("Path is local\n");
      } else {
         pick_server(config, &path, &hostaddr, portno);
         if (path == &(config->defaultserver)) {
            printf("Path is via default server:\n");
            show_server(config, path, 1);
         } else {
            printf("Host is reached via this path:\n");
            show_server(config, path, 0);
         }
      }
	}

	return;
}

void show_conf(struct parsedfile *config) {
	struct netent *net;
	struct serverent *server;

	/* Show the local networks */
	printf("=== Local networks (no socks server needed) ===\n");
	net = (config->localnets);
	while (net != NULL) {
		printf("Network: %15s ",
		       inet_ntoa(net->localip));
		printf("NetMask: %15s\n", 
		       inet_ntoa(net->localnet));
		net = net->next;
	}
	printf("\n");

	/* If we have a default server configuration show it */
	printf("=== Default Server Configuration ===\n");
	if ((config->defaultserver).address != NULL) {
		show_server(config, &(config->defaultserver), 1);
	} else {
		printf("No default server specified, this is rarely a "
		       "good idea\n");
	}
	printf("\n");

	/* Now show paths */
	if ((config->paths) != NULL) {
		server = (config->paths);
		while (server != NULL) {
			printf("=== Path (line no %d in configuration file)"
			       " ===\n", server->lineno);
			show_server(config, server, 0);
			printf("\n");
			server = server->next;
		}	
	} 

#ifdef USE_TOR_DNS
    /* Show tordns configuration options */
    printf("=== TorDNS Configuration Options ===\n");
    printf("Tor DNS enabled:        %s\n", 
           config->tordns_enabled ? "yes" : "no");
    printf("Tor DNS deadpool range: %s/", 
           inet_ntoa(config->tordns_deadpool_range->localip));
    printf("%s\n", 
        inet_ntoa(config->tordns_deadpool_range->localnet));
    printf("Tor DNS cache size:     %d\n", config->tordns_cache_size);
    printf("\n");
#endif

    return;
}

void show_server(struct parsedfile *config, struct serverent *server, int def) {
	struct in_addr res;
	struct netent *net;

	/* Show address */
	if (server->address != NULL) 
		printf("Server:       %s (%s)\n", server->address, 
	       		((res.s_addr = resolve_ip(server->address, 0, 
						  HOSTNAMES)) == 0 
			 ? "Invalid!" : inet_ntoa(res)));
	else
		printf("Server:       ERROR! None specified\n");

	/* Check the server is on a local net */
	if ((server->address != NULL) && (res.s_addr != 0) && 
	    (is_local(config, &res))) 
		fprintf(stderr, "Error: Server is not on a network "
				"specified as local\n");

	/* Show port */
	printf("Port:         %d\n", server->port);

	/* Show SOCKS type */
	printf("SOCKS type:   %d\n", server->type);

	/* Show default username and password info */
	if (server->type == 5) {
		/* Show the default user info */
		printf("Default user: %s\n", 
		       (server->defuser == NULL) ? 
		       "Not Specified" : server->defuser);
		printf("Default pass: %s\n", 
		       (server->defpass == NULL) ? 
		       "Not Specified" : "******** (Hidden)");
		if ((server->defuser == NULL) && 
		    (server->defpass != NULL)) 
			fprintf(stderr, "Error: Default user must be specified "
				   "if default pass is specified\n");
	} else {
		if (server->defuser) printf("Default user: %s\n", 
					    server->defuser);
		if (server->defpass) printf("Default pass: %s\n", 
					    server->defpass);
		if ((server->defuser != NULL) || (server->defpass != NULL))
			fprintf(stderr, "Error: Default user and password "
				   "may only be specified for version 5 "
				   "servers\n");
	}

	/* If this is the default servers and it has reachnets, thats stupid */
	if (def) {
		if (server->reachnets != NULL) { 
			fprintf(stderr, "Error: The default server has "
			       "specified networks it can reach (reach statements), "
			       "these statements are ignored since the "
			       "default server will be tried for any network "
			       "which is not specified in a reach statement "
			       "for other servers\n");
		}
	} else if (server->reachnets == NULL) {
		fprintf(stderr, "Error: No reach statements specified for "
		       "server, this server will never be used\n");
	} else {
		printf("This server can be used to reach:\n");
		net = server->reachnets;
		while (net != NULL) {
			printf("Network: %15s ",
			       inet_ntoa(net->localip));
			printf("NetMask: %15s ", 
			       inet_ntoa(net->localnet));
         if (net->startport)
            printf("Ports: %5lu - %5lu",
                   net->startport, net->endport);
         printf("\n");
			net = net->next;
		}
	}
}
