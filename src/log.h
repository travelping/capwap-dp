#ifndef __LOG_H
#define __LOG_H

#include <string.h>
#define __FILE_NAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

#ifdef USE_SYSTEMD_JOURNAL

#include <systemd/sd-journal.h>

#define _log_XSTRINGIFY(x) #x
#define _log_STRINGIFY(x) _log_XSTRINGIFY(x)

#define ALLOCA_CODE_FILE(f, file)                 \
	do {                                      \
		size_t _fl;                       \
		const char *_file = (file);       \
		char **_f = &(f);                 \
		_fl = strlen(_file) + 1;          \
		*_f = alloca(_fl + 10);           \
		memcpy(*_f, "CODE_FILE=", 10);    \
		memcpy(*_f + 10, _file, _fl);     \
	} while(0)

#define log(priority, ...)						\
	do {								\
		char *f;						\
		ALLOCA_CODE_FILE(f, __FILE_NAME__);			\
		sd_journal_print_with_location(priority, f, "CODE_LINE=" _log_STRINGIFY(__LINE__), __func__, __VA_ARGS__); \
	} while (0)

#else

#include <syslog.h>

#define log(priority, ...)	syslog(priority, __VA_ARGS__)

#endif

#if defined(DEBUG)

#define debug(...)						\
	_debug(__FILE_NAME__, __LINE__, __func__,__VA_ARGS__)
#define debug_head(tv)						\
	_debug_head(__FILE_NAME__, __LINE__, __func__, tv)

void debug_log(const char *fmt, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
void debug_flush(void);

void _debug(const char *filename, int line, const char *func, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 4, 5)));
void _debug_head(const char *filename, int line, const char *func, struct timeval *);

#else

#define debug(format, ...) do {} while (0)

#define debug_head() do {} while (0)
#define debug_log(format, ...) do {} while (0)
#define debug_flush() do {} while (0)

#endif

#endif /* __LOG_H */
