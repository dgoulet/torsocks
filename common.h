/* Common functions provided in common.c */
/* GCC has several useful attributes. */
#if defined(__GNUC__) && __GNUC__ >= 3
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_PURE __attribute__((pure))
#define ATTR_CONST __attribute__((const))
#define ATTR_MALLOC __attribute__((malloc))
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_NONNULL(x) __attribute__((nonnull x))
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be true. */
#define PREDICT_LIKELY(exp) __builtin_expect((exp), 1)
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be false. */
#define PREDICT_UNLIKELY(exp) __builtin_expect((exp), 0)
#else
#define ATTR_NORETURN
#define ATTR_PURE
#define ATTR_CONST
#define ATTR_MALLOC
#define ATTR_NORETURN
#define ATTR_NONNULL(x)
#define PREDICT_LIKELY(exp) (exp)
#define PREDICT_UNLIKELY(exp) (exp)
#endif

uint16_t get_uint16(const char *cp) ATTR_PURE ATTR_NONNULL((1));
uint32_t get_uint32(const char *cp) ATTR_PURE ATTR_NONNULL((1));
void set_uint16(char *cp, uint16_t v) ATTR_NONNULL((1));
void set_uint32(char *cp, uint32_t v) ATTR_NONNULL((1));

void set_log_options(int, char *, int);
void show_msg(int level, const char *, ...);
int count_netmask_bits(uint32_t mask);
unsigned int resolve_ip(char *, int, int);

#define MSGNONE   -1
#define MSGERR    0
#define MSGWARN   1
#define MSGNOTICE 2
#define MSGDEBUG  2
