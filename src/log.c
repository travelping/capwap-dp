/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2014 Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>

#include "log.h"

#if defined(DEBUG)

static __thread int save_errno;

static __thread size_t pos = 0;
static __thread char buf[128 * 1024];

static __thread int ctime_last = 0;
static __thread char ctime_buf[27];

void _debug(const char *filename, int line, const char *func, const char *fmt, ...)
{
	va_list args;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	_debug_head(filename, line, func, &tv);

	va_start(args, fmt);
	pos += vsnprintf(buf + pos, sizeof(buf) - pos, fmt, args);
	va_end(args);

	debug_flush();
}

void _debug_head(const char *filename, int line, const char *func, struct timeval *tv)
{
	save_errno = errno;

	if (ctime_last != tv->tv_sec) {
		ctime_r(&tv->tv_sec, ctime_buf);
		ctime_last = tv->tv_sec;
	}

	pos += snprintf(buf + pos, sizeof(buf) - pos, "%.15s.%03ld %s:%d:%s [%lX]: ",
			&ctime_buf[4], tv->tv_usec / 1000,
			filename, line, func, pthread_self());
}

void debug_log(const char *fmt, ...)
{
	va_list args;

	/* make sure %m gets the right errno */
	errno = save_errno;

	va_start(args, fmt);
	pos += vsnprintf(buf + pos, sizeof(buf) - pos, fmt, args);
	va_end(args);

	assert(pos < sizeof(buf));
}

void debug_flush()
{
	if (pos > 0 && pos < sizeof(buf) && buf[pos - 1] != '\n')
		buf[pos++] = '\n';

	if (write(STDERR_FILENO, buf, pos) < 0)
		;
	pos = 0;
	errno = save_errno;
}

#endif
