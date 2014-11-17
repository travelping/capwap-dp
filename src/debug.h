#ifndef __DEBUG_H
#define __DEBUG_H

#if !defined(NDEBUG)

void debug(const char *fmt, ...) __attribute__ ((__format__ (__printf__, 1, 2)));

void debug_head(struct timeval *);
void debug_log(const char *fmt, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
void debug_flush();

#else

#define debug(format, ...) do {} while (0)

#define debug_head() do {} while (0)
#define debug_log(format, ...) do {} while (0)
#define debug_flush() do {} while (0)

#endif

#endif /* __DEBUG_H */
