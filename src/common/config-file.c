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

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <config.h>

#include "config-file.h"
#include "log.h"
#include "utils.h"

/* Global configuration variables. */
static struct config_server_entry *currentcontext = NULL;

/* Check server entries (and establish defaults) */
static int check_server(struct config_server_entry *server)
{
    /* Default to the default Tor Socks port */
    if (server->port == 0) {
        server->port = 9050;
    }

    /* Default to a presumably local installation of Tor */
    if (server->address == NULL) {
        server->address = strdup("127.0.0.1");
    }

    /* Default to SOCKS V4 */
    if (server->type == 0) {
        server->type = 4;
    }

    return(0);
}

static int handle_endpath(struct config_parsed *config, int lineno, int nowords) {

	if (nowords != 1) {
		ERR("Badly formed path close statement on line  %d in configuration"
				"file (should look like \"}\")\n", lineno);
	} else {
		currentcontext = &(config->default_server);
	}

	/* We could perform some checking on the validty of data in */
	/* the completed path here, but thats what verifyconf is    */
	/* designed to do, no point in weighing down libtorsocks      */

	return(0);
}

/* Construct a config_network_entry given a string like                             */
/* "198.126.0.1[:portno[-portno]]/255.255.255.0"                      */
int make_config_network_entry(char *value, struct config_network_entry **ent) {
	char *ip;
	char *subnet;
	char *start_port = NULL;
	char *end_port = NULL;
	char *badchar;
	char separator;
	static char buf[200];
	char *split;

	/* Get a copy of the string so we can modify it */
	strncpy(buf, value, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = (char) 0;
	split = buf;

	/* Now rip it up */
	ip = utils_strsplit(&separator, &split, "/:");
	if (separator == ':') {
		/* We have a start port */
		start_port = utils_strsplit(&separator, &split, "-/");
		if (separator == '-') 
			/* We have an end port */
			end_port = utils_strsplit(&separator, &split, "/");
	}
	subnet = utils_strsplit(NULL, &split, " \n");

	if ((ip == NULL) || (subnet == NULL)) {
		/* Network specification not validly constructed */
		return(1);
	}

	/* Allocate the new entry */
	if ((*ent = (struct config_network_entry *) malloc(sizeof(struct config_network_entry)))
			== NULL) {
		/* If we couldn't malloc some storage, leave */
		exit(1);
	}

	DBG("New network entry for %s going to 0x%08x\n", ip, *ent);

	if (!start_port)
		(*ent)->start_port = 0;
	if (!end_port)
		(*ent)->end_port = 0;

#ifdef HAVE_INET_ADDR
	if (((*ent)->local_ip.s_addr = inet_addr(ip)) == -1) {
#elif defined(HAVE_INET_ATON)
		if (!(inet_aton(ip, &((*ent)->local_ip)))) {
#endif
			/* Badly constructed IP */
			free(*ent);
			return(2);
		}
#ifdef HAVE_INET_ADDR
		else if (((*ent)->local_net.s_addr = inet_addr(subnet)) == -1) {
#elif defined(HAVE_INET_ATON)
			else if (!(inet_aton(subnet, &((*ent)->local_net)))) {
#endif
				/* Badly constructed subnet */
				free(*ent);
				return(3);
			} else if (((*ent)->local_ip.s_addr &
						(*ent)->local_net.s_addr) != 
					(*ent)->local_ip.s_addr) {
				/* Subnet and Ip != Ip */
				free(*ent);
				return(4);
			} else if (start_port && 
					(!((*ent)->start_port = strtol(start_port, &badchar, 10)) || 
					 (*badchar != 0) || ((*ent)->start_port > 65535))) {
				/* Bad start port */
				free(*ent);
				return(5);
			} else if (end_port && 
					(!((*ent)->end_port = strtol(end_port, &badchar, 10)) || 
					 (*badchar != 0) || ((*ent)->end_port > 65535))) {
				/* Bad end port */
				free(*ent);
				return(6);
			} else if (((*ent)->start_port > (*ent)->end_port) && !(start_port && !end_port)) {
				/* End port is less than start port */
				free(*ent);
				return(7);
			}

			if (start_port && !end_port)
				(*ent)->end_port = (*ent)->start_port;

			return(0);
		}


static int handle_reaches(int lineno, char *value) {
	int rc;
	struct config_network_entry *ent;

	rc = make_config_network_entry(value, &ent);
	switch(rc) {
		case 1:
			ERR("Local network specification (%s) is not validly "
					"constructed in reach statement on line "
					"%d in configuration "
					"file\n", value, lineno);
			return(0);
			break;
		case 2:
			ERR("IP in reach statement "
					"network specification (%s) is not valid on line "
					"%d in configuration file\n", value, lineno);
			return(0);
			break;
		case 3:
			ERR("SUBNET in reach statement "
					"network specification (%s) is not valid on "
					"line %d in configuration file\n", value,
					lineno);
			return(0);
			break;
		case 4:
			ERR("IP (%s) & ", inet_ntoa(ent->local_ip));
			ERR("SUBNET (%s) != IP on line %d in "
					"configuration file, ignored\n",
					inet_ntoa(ent->local_net), lineno);
			return(0);
			break;
		case 5:
			ERR("Start port in reach statement "
					"network specification (%s) is not valid on line "
					"%d in configuration file\n", value, lineno);
			return(0);
			break;
		case 6:
			ERR("End port in reach statement "
					"network specification (%s) is not valid on line "
					"%d in configuration file\n", value, lineno);
			return(0);
			break;
		case 7:
			ERR("End port in reach statement "
					"network specification (%s) is less than the start "
					"port on line %d in configuration file\n", value, 
					lineno);
			return(0);
			break;
	}

	/* The entry is valid so add it to linked list */
	ent -> next = currentcontext -> reachnets;
	currentcontext -> reachnets = ent;

	return(0);
}

static int handle_server(struct config_parsed *config, int lineno, char *value) {
	char *ip;

	ip = utils_strsplit(NULL, &value, " ");

	/* We don't verify this ip/hostname at this stage, */
	/* its resolved immediately before use in torsocks.c */
	if (currentcontext->address == NULL)
		currentcontext->address = strdup(ip);
	else {
		if (currentcontext == &(config->default_server))
			ERR("Only one default SOCKS server "
					"may be specified at line %d in "
					"configuration file\n", lineno);
		else
			ERR("Only one SOCKS server may be specified "
					"per path on line %d in configuration "
					"file. (Path begins on line %d)\n",
					lineno, currentcontext->lineno);
	}

	return(0);
}

static int handle_port(struct config_parsed *config, int lineno, char *value) {

	if (currentcontext->port != 0) {
		if (currentcontext == &(config->default_server))
			ERR("Server port may only be specified "
					"once for default server, at line %d "
					"in configuration file\n", lineno);
		else
			ERR("Server port may only be specified "
					"once per path on line %d in configuration "
					"file. (Path begins on line %d)\n",
					lineno, currentcontext->lineno);
	} else {
		errno = 0;
		currentcontext->port = (unsigned short int)
			(strtol(value, (char **)NULL, 10));
		if ((errno != 0) || (currentcontext->port == 0)) {
			ERR("Invalid server port number "
					"specified in configuration file "
					"(%s) on line %d\n", value, lineno);
			currentcontext->port = 0;
		}
	}

	return(0);
}

static int handle_username(struct config_parsed *config, int lineno, char *value) {

	if (currentcontext->username != NULL) {
		if (currentcontext == &(config->default_server))
			ERR("Default username may only be specified "
					"once for default server, at line %d "
					"in configuration file\n", lineno);
		else
			ERR("Default username may only be specified "
					"once per path on line %d in configuration "
					"file. (Path begins on line %d)\n",
					lineno, currentcontext->lineno);
	} else {
		currentcontext->username = strdup(value);
	}

	return(0);
}

static int handle_password(struct config_parsed *config, int lineno, char *value) {

	if (currentcontext->password != NULL) {
		if (currentcontext == &(config->default_server))
			ERR("Default password may only be specified "
					"once for default server, at line %d "
					"in configuration file\n", lineno);
		else
			ERR("Default password may only be specified "
					"once per path on line %d in configuration "
					"file. (Path begins on line %d)\n",
					lineno, currentcontext->lineno);
	} else {
		currentcontext->password = strdup(value);
	}

	return(0);
}

static int handle_type(struct config_parsed *config, int lineno, char *value) {

	if (currentcontext->type != 0) {
		if (currentcontext == &(config->default_server))
			ERR("Server type may only be specified "
					"once for default server, at line %d "
					"in configuration file\n", lineno);
		else
			ERR("Server type may only be specified "
					"once per path on line %d in configuration "
					"file. (Path begins on line %d)\n",
					lineno, currentcontext->lineno);
	} else {
		errno = 0;
		currentcontext->type = (int) strtol(value, (char **)NULL, 10);
		if ((errno != 0) || (currentcontext->type == 0) ||
				((currentcontext->type != 4) && (currentcontext->type != 5))) {
			ERR("Invalid server type (%s) "
					"specified in configuration file "
					"on line %d, only 4 or 5 may be "
					"specified\n", value, lineno);
			currentcontext->type = 0;
		}
	}

	return(0);
}

static int handle_flag(char *value) 
{
	if(!strcasecmp(value, "true") || !strcasecmp(value, "yes")  
			|| !strcmp(value, "1")) {
		return 1;
	} else if (!strcasecmp(value, "false") || !strcasecmp(value, "no") 
			|| !strcmp(value, "0")) {
		return 0;
	} else {
		return -1;
	}
}

static int handle_tordns_enabled(struct config_parsed *config, int lineno,
		char *value)
{
	int val = handle_flag(value);
	if(val == -1) {
		ERR("Invalid value %s supplied for tordns_enabled at "
				"line %d in config file, IGNORED\n", value, lineno);
	} else {
		config->tordns_enabled = val;
	}
	return 0;
}

static int handle_tordns_cache_size(struct config_parsed *config,
		char *value)
{
	char *endptr;
	long size = strtol(value, &endptr, 10);
	if(*endptr != '\0') {
		ERR("Error parsing integer value for "
				"tordns_cache_size (%s), using default %d\n", 
				value, config->tordns_cache_size);
	} else if(size < 128) {
		ERR("The value supplied for tordns_cache_size (%d) "
				"is too small (<128), using default %d\n", size, 
				config->tordns_cache_size);
	} else if(size > 4096) {
		ERR("The value supplied for tordns_cache_range (%d) "
				"is too large (>4096), using default %d\n", size, 
				config->tordns_cache_size);
	} else {
		config->tordns_cache_size = size;
	}
	return 0;
}

static int handle_path(struct config_parsed *config, int lineno, int nowords, char *words[])
{
	struct config_server_entry *newserver;

	if ((nowords != 2) || (strcmp(words[1], "{"))) {
		ERR("Badly formed path open statement on line %d "
				"in configuration file (should look like "
				"\"path {\")\n", lineno);
	} else if (currentcontext != &(config->default_server)) {
		/* You cannot nest path statements so check that */
		/* the current context is default_server          */
		ERR("Path statements cannot be nested on line %d "
				"in configuration file\n", lineno);
	} else {
		/* Open up a new config_server_entry, put it on the list   */
		/* then set the current context                  */
		if ((newserver = malloc(sizeof(*newserver))) == NULL)
			exit(-1);

		/* Initialize the structure */
		DBG("New server structure from line %d in configuration file going "
				"to 0x%08x\n", lineno, newserver);
		memset(newserver, 0x0, sizeof(*newserver));
		newserver->next = config->paths;
		newserver->lineno = lineno;
		config->paths = newserver;
		currentcontext = newserver;
	}

	return(0);
}

static int handle_local(struct config_parsed *config, int lineno, const char *value) {
	int rc;
	struct config_network_entry *ent;

	if (currentcontext != &(config->default_server)) {
		ERR("Local networks cannot be specified in path "
				"block at line %d in configuration file. "
				"(Path block started at line %d)\n",
				lineno, currentcontext->lineno);
		return(0);
	}

	rc = make_config_network_entry((char *)value, &ent);
	switch(rc) {
		case 1:
			ERR("Local network specification (%s) is not validly "
					"constructed on line %d in configuration "
					"file\n", value, lineno);
			return(0);
			break;
		case 2:
			ERR("IP for local "
					"network specification (%s) is not valid on line "
					"%d in configuration file\n", value, lineno);
			return(0);
			break;
		case 3:
			ERR("SUBNET for "
					"local network specification (%s) is not valid on "
					"line %d in configuration file\n", value,
					lineno);
			return(0);
			break;
		case 4:
			ERR("IP (%s) & ", inet_ntoa(ent->local_ip));
			ERR("SUBNET (%s) != IP on line %d in "
					"configuration file, ignored\n",
					inet_ntoa(ent->local_net), lineno);
			return(0);
		case 5:
		case 6:
		case 7:
			ERR("Port specification is invalid and "
					"not allowed in local network specification "
					"(%s) on line %d in configuration file\n",
					value, lineno);
			return(0);
			break;
	}

	if (ent->start_port || ent->end_port) {
		ERR("Port specification is "
				"not allowed in local network specification "
				"(%s) on line %d in configuration file\n",
				value, lineno);
		return(0);
	}

	/* The entry is valid so add it to linked list */
	ent -> next = config->local_nets;
	(config->local_nets) = ent;

	return(0);
}

static int handle_tordns_deadpool_range(struct config_parsed *config, int lineno, 
		const char *value)
{
	int rc;
	struct config_network_entry *ent;

	if (config->tordns_deadpool_range != NULL) {
		ERR("Only one 'deadpool' entry permitted, found a "
				"second at line %d in configuration file.\n");
		return(0);
	}

	if (currentcontext != &(config->default_server)) {
		ERR("Deadpool cannot be specified in path "
				"block at line %d in configuration file. "
				"(Path block started at line %d)\n",
				lineno, currentcontext->lineno);
		return(0);
	}

	rc = make_config_network_entry((char *)value, &ent);
	/* This is copied from handle_local and should probably be folded into
	   a generic whinge() function or something */
	switch(rc) {
		case 1:
			ERR("The deadpool specification (%s) is not validly "
					"constructed on line %d in configuration "
					"file\n", value, lineno);
			return(0);
			break;
		case 2:
			ERR("IP for deadpool "
					"network specification (%s) is not valid on line "
					"%d in configuration file\n", value, lineno);
			return(0);
			break;
		case 3:
			ERR("SUBNET for " 
					"deadpool network specification (%s) is not valid on "
					"line %d in configuration file\n", value, 
					lineno);
			return(0);
			break;
		case 4:
			ERR("IP (%s) & ", inet_ntoa(ent->local_ip));
			ERR("SUBNET (%s) != IP on line %d in "
					"configuration file, ignored\n",
					inet_ntoa(ent->local_net), lineno);
			return(0);
		case 5:
		case 6:
		case 7:
			ERR("Port specification is invalid and "
					"not allowed in deadpool specification "
					"(%s) on line %d in configuration file\n",
					value, lineno);
			return(0);
			break;
	}
	if (ent->start_port || ent->end_port) {
		ERR("Port specification is "
				"not allowed in deadpool specification "
				"(%s) on line %d in configuration file\n",
				value, lineno);
		return(0);
	}

	config->tordns_deadpool_range = ent;
	return 0;
}

static int handle_line(struct config_parsed *config, char *line, int lineno)
{
    char *words[10];
    static char savedline[CONFIG_MAXLINE];
    int   nowords = 0, i;

    /* Save the input string */
    strncpy(savedline, line, CONFIG_MAXLINE - 1);
    savedline[CONFIG_MAXLINE - 1] = (char) 0;
    /* Tokenize the input string */
    nowords = utils_tokenize_ignore_comments(line, 10, words);

    /* Set the spare slots to an empty string to simplify */
    /* processing                                         */
    for (i = nowords; i < 10; i++)
        words[i] = NULL;

    if (nowords > 0) {
        /* Now this can either be a "path" block starter or */
        /* ender, otherwise it has to be a pair (<name> =   */
        /* <value>)                                         */
        if (!strcmp(words[0], "path")) {
            handle_path(config, lineno, nowords, words);
        } else if (!strcmp(words[0], "}")) {
            handle_endpath(config, lineno, nowords);
        } else {
            /* Has to be a pair */
            if ((nowords != 3) || (strcmp(words[1], "="))) {
                ERR("Malformed configuration pair "
                       "on line %d in configuration "
                       "file, \"%s\"\n", lineno, savedline);
            } else if (!strcmp(words[0], "reaches")) {
                handle_reaches(lineno, words[2]);
            } else if (!strcmp(words[0], "server")) {
                handle_server(config, lineno, words[2]);
            } else if (!strcmp(words[0], "server_port")) {
                handle_port(config, lineno, words[2]);
            } else if (!strcmp(words[0], "server_type")) {
                handle_type(config, lineno, words[2]);
            } else if (!strcmp(words[0], "default_user")) {
                handle_username(config, lineno, words[2]);
            } else if (!strcmp(words[0], "default_pass")) {
                handle_password(config, lineno, words[2]);
            } else if (!strcmp(words[0], "local")) {
                handle_local(config, lineno, words[2]);
            } else if (!strcmp(words[0], "tordns_enable")) {
                handle_tordns_enabled(config, lineno, words[2]);
            } else if (!strcmp(words[0], "tordns_deadpool_range")) {
                handle_tordns_deadpool_range(config, lineno, words[2]);
            } else if (!strcmp(words[0], "tordns_cache_size")) {
                handle_tordns_cache_size(config, words[2]);
            } else {
                ERR("Invalid pair type (%s) specified "
                       "on line %d in configuration file, "
                       "\"%s\"\n", words[0], lineno,
                       savedline);
            }
        }
    }

    return(0);
}

int is_local(struct config_parsed *config, struct in_addr *testip) {
    struct config_network_entry *ent;
    char buf[16];
    inet_ntop(AF_INET, testip, buf, sizeof(buf));
    DBG("checking if address: %s is local"
                        "\n",
                        buf);

    for (ent = (config->local_nets); ent != NULL; ent = ent -> next) {
        inet_ntop(AF_INET, &ent->local_net, buf, sizeof(buf));
        DBG("local_net addr: %s"
                            "\n",
                            buf);
        inet_ntop(AF_INET, &ent->local_ip, buf, sizeof(buf));
        DBG("local_ip addr: %s"
                            "\n",
                            buf);
        DBG("result testip->s_addr & ent->local_net.s_addr : %i"
                            "\n",
                            testip->s_addr & ent->local_net.s_addr);
        DBG("result ent->local_ip.s_addr & ent->local_net.s_addr : %i"
                            "\n",
                            ent->local_ip.s_addr & ent->local_net.s_addr);
        DBG("result ent->local_ip.s_addr : %i"
                            "\n",
                            ent->local_ip.s_addr);
        if ((testip->s_addr & ent->local_net.s_addr) ==
            (ent->local_ip.s_addr & ent->local_net.s_addr))  {
            DBG("address: %s is local"
                                "\n",
                                buf);
            return(0);
        }
    }

    inet_ntop(AF_INET, testip, buf, sizeof(buf));
    DBG("address: %s is not local"
                        "\n",
                        buf);
    return(1);
}

/* Find the appropriate server to reach an ip */
int pick_server(struct config_parsed *config, struct config_server_entry **ent, 
                struct in_addr *ip, unsigned int port) {
    struct config_network_entry *net;
   char ipbuf[64];

   DBG("Picking appropriate server for %s\n", inet_ntoa(*ip));
    *ent = (config->paths);
    while (*ent != NULL) {
        /* Go through all the servers looking for one */
        /* with a path to this network                */
        DBG("Checking SOCKS server %s\n", 
                ((*ent)->address ? (*ent)->address : "(No Address)"));
        net = (*ent)->reachnets;
        while (net != NULL) {
         strcpy(ipbuf, inet_ntoa(net->local_ip));
         DBG("Server can reach %s/%s\n", 
                  ipbuf, inet_ntoa(net->local_net));
            if (((ip->s_addr & net->local_net.s_addr) ==
                (net->local_ip.s_addr & net->local_net.s_addr)) &&
                (!net->start_port || 
                ((net->start_port <= port) && (net->end_port >= port))))  
            {
                DBG("This server can reach target\n");
                    /* Found the net, return */
                    return(0);
            }
            net = net->next;
        }
        (*ent) = (*ent)->next;
    }

    *ent = &(config->default_server);

    return(0);
}

/*
 * Read and populate the given config parsed data structure.
 *
 * Return 0 on success or else a negative value.
 */
int config_file_read(const char *filename, struct config_parsed *config)
{
	FILE *conf;
	char line[CONFIG_MAXLINE];
	int rc = 0;
	int lineno = 1;
	struct config_server_entry *server;

	/* Clear out the structure */
	memset(config, 0x0, sizeof(*config));

	/* Initialization */
	currentcontext = &(config->default_server);

	/* Tordns defaults */
	config->tordns_cache_size = 256;
	config->tordns_enabled = 1;


	/* If a filename wasn't provided, use the default */
	if (filename == NULL) {
		strncpy(line, CONF_FILE, sizeof(line) - 1);
		/* Insure null termination */
		line[sizeof(line) - 1] = (char) 0;
		filename = line;
		DBG("Configuration file not provided by TORSOCKS_CONF_FILE "
				"environment variable, attempting to use defaults in %s.\n", filename);
	}

	/* If there is no configuration file use reasonable defaults for Tor */
	if ((conf = fopen(filename, "r")) == NULL) {
		ERR("Could not open socks configuration file "
				"(%s) errno (%d), assuming sensible defaults for Tor.\n", filename, errno);
		memset(&(config->default_server), 0x0, sizeof(config->default_server));
		check_server(&(config->default_server));
		handle_local(config, 0, "127.0.0.0/255.0.0.0");
		handle_local(config, 0, "10.0.0.0/255.0.0.0");
		handle_local(config, 0, "192.168.0.0/255.255.0.0");
		handle_local(config, 0, "172.16.0.0/255.240.0.0");
		handle_local(config, 0, "169.254.0.0/255.255.0.0");
		rc = 1; /* Severe errors reading configuration */
	} else {
		memset(&(config->default_server), 0x0, sizeof(config->default_server));

		while (NULL != fgets(line, CONFIG_MAXLINE, conf)) {
			/* This line _SHOULD_ end in \n so we  */
			/* just chop off the \n and hand it on */
			if (strlen(line) > 0)
				line[strlen(line) - 1] = '\0';
			handle_line(config, line, lineno);
			lineno++;
		}
		fclose(conf);

		/* Always add the 127.0.0.1/255.0.0.0 subnet to local */
		handle_local(config, 0, "127.0.0.0/255.0.0.0");
		/* We always consider this local, because many users' dsl
		   routers act as their DNS. */
		handle_local(config, 0, "10.0.0.0/255.0.0.0");
		handle_local(config, 0, "192.168.0.0/255.255.0.0");
		handle_local(config, 0, "172.16.0.0/255.240.0.0");
		handle_local(config, 0, "169.254.0.0/255.255.0.0");
		handle_local(config, 0, "192.168.0.0/255.255.0.0");

		/* Check default server */
		check_server(&(config->default_server));
		server = (config->paths);
		while (server != NULL) {
			check_server(server);
			server = server->next;
		}
	}

	/* Initialize tordns deadpool_range if not supplied */
	if(config->tordns_deadpool_range == NULL) {
		handle_tordns_deadpool_range(config, 0, "127.0.69.0/255.255.255.0");
	}

	return(rc);
}
