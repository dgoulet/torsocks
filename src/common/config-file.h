/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org> 
 * 				 2008-2011 - Robert Hogan <robert@roberthogan.net>
 * 				 	  2013 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CONFIG_FILE_H
#define CONFIG_FILE_H

#include <netinet/in.h>

/* Max length of a configuration line. */
#define CONFIG_MAXLINE BUFSIZ

/*
 * Structure representing one server entry specified in the config.
 */
struct config_server_entry {
	/* Line number in conf file this path started on. */
    int lineno;
	/* Address/hostname of server. */
    const char *address;
	/* Port number of server. */
    in_port_t port;
	/* Type of server (4/5). */
    int type;
	/* Username for this socks server. */
    const char *username;
	/* Password for this socks server. */
    const char *password;
	/* Linked list of nets from this serveri. */
    struct config_network_entry *reachnets;
	/* Pointer to next server entry. */
    struct config_server_entry *next;
};

/*
 * Structure representing a network.
 */
struct config_network_entry {
	/* Base IP of the network */
   struct in_addr local_ip;
   /* Mask for the network */
   struct in_addr local_net;
   /* Range of ports for the network */
   in_port_t start_port;
   in_port_t end_port;
   /* Pointer to next network entry */
   struct config_network_entry *next;
};

/*
 * Structure representing a complete parsed file.
 */
struct config_parsed {
   struct config_network_entry *local_nets;
   struct config_server_entry default_server;
   struct config_server_entry *paths;
   int tordns_enabled;
   int tordns_failopen;
   unsigned int tordns_cache_size;
   struct config_network_entry *tordns_deadpool_range;
};

/* Functions provided by parser module */
int config_file_read(const char *filename, struct config_parsed *config);

int is_local(struct config_parsed *, struct in_addr *);
int pick_server(struct config_parsed *, struct config_server_entry **, struct in_addr *, unsigned int port);
char *strsplit(char *separator, char **text, const char *search);

#endif /* CONFIG_FILE_H */
