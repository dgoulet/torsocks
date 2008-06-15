/* accconfig.h -- `autoheader' will generate config.h.in for tsocks . */

/* Allow tsocks to generate messages to stderr when errors are
encountered, this is really important and should only be disabled if
you're REALLY sure. It can also be turned off at run time, see the man
page for details */
#undef ALLOW_MSG_OUTPUT

/* Allow TSOCKS_CONF_FILE in environment to specify config file 
location */
#undef ALLOW_ENV_CONFIG

/* Use _GNU_SOURCE to define RTLD_NEXT, mostly for RH7 systems */
#undef USE_GNU_SOURCE

/* dlopen() the old libc to get connect() instead of RTLD_NEXT, 
hopefully shouldn't be needed */
#undef USE_OLD_DLSYM

/* path to library containing connect(), needed if USE_OLD_DLSYM is enabled */
#undef LIBCONNECT

/* path to libc, needed if USE_OLD_DLSYM is enabled */
#undef LIBC

/* Configure the system resolver to use TCP queries on startup, this
allows socksified DNS */
#undef USE_SOCKS_DNS

/* Prototype and function header for connect function */
#undef CONNECT_SIGNATURE

/* The type of socket structure pointer to use to call the 
 * real connect */
#undef CONNECT_SOCKARG

/* Prototype and function header for select function */
#undef SELECT_SIGNATURE

/* Prototype and function header for poll function */
#undef POLL_SIGNATURE

/* Prototype and function header for close function */
#undef CLOSE_SIGNATURE

/* Prototype and function header for getpeername function */
#undef GETPEERNAME_SIGNATURE

/* Work out which function we have for conversion from string IPs to 
numerical ones */
#undef HAVE_INET_ADDR
#undef HAVE_INET_ATON

/* We use strsep which isn't on all machines, but we provide our own
definition of it for those which don't have it, this causes us to define
our version */
#undef DEFINE_STRSEP

/* Should we resolve DNS entries in a way which works well with tor? */
#undef USE_TOR_DNS

/* Allow the use of DNS names in the socks configuration file for socks
servers. This doesn't work if socksified DNS is enabled for obvious
reasons, it also introduces overhead, but people seem to want it */
#define HOSTNAMES 0

/* We need the gethostbyname() function to do dns lookups in tsocks or 
in inspectsocks */
#undef HAVE_GETHOSTBYNAME

/* Location of configuration file (typically /etc/tsocks.conf) */
#undef CONF_FILE 

/* Define to indicate the correct signature for gethostbyname_r */
#undef HAVE_FUNC_GETHOSTBYNAME_R_6
#undef HAVE_FUNC_GETHOSTBYNAME_R_5
#undef HAVE_FUNC_GETHOSTBYNAME_R_3

/* Signatures for name resolution stuff */
#undef GETHOSTBYNAME_SIGNATURE
#undef GETADDRINFO_SIGNATURE
#undef GETIPNODEBYNAME_SIGNATURE

