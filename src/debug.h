#ifndef __DEBUG_H
#define __DEBUG_H

#define debug(format, ...)			\
	do {					\
		debug_log(format, ##__VA_ARGS__); \
		debug_flush();			\
	} while (0)

#if !defined(NDEBUG)

void debug_log(const char *fmt, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
void debug_flush();

#else

#define debug_log(format, ...) do {} while (0)
#define debug_flush() do {} while (0)

#endif

#endif /* __DEBUG_H */
