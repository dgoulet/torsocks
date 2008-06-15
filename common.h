/* Common functions provided in common.c */

void set_log_options(int, char *, int);
void show_msg(int level, const char *, ...);
int count_netmask_bits(uint32_t mask);
unsigned int resolve_ip(char *, int, int);

#define MSGNONE   -1
#define MSGERR    0
#define MSGWARN   1
#define MSGNOTICE 2
#define MSGDEBUG  2
