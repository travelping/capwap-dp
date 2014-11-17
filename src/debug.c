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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>

#include "debug.h"

#if !defined(NDEBUG)

static __thread char buf[4069];
static __thread size_t pos = 0;

static __thread int ctime_last = 0;
static __thread char ctime_buf[27];

void debug(const char *fmt, ...)
{
        va_list args;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	debug_head(&tv);

        va_start(args, fmt);
        pos += vsnprintf(buf + pos, sizeof(buf) - pos, fmt, args);
        va_end(args);

	debug_flush();
}

void debug_head(struct timeval *tv)
{
        if (ctime_last != tv->tv_sec) {
                ctime_r(&tv->tv_sec, ctime_buf);
                ctime_last = tv->tv_sec;
        }

        pos += snprintf(buf + pos, sizeof(buf) - pos, "%.15s.%03ld [%lX]: ", &ctime_buf[4], tv->tv_usec / 1000, pthread_self());
}

void debug_log(const char *fmt, ...)
{
        va_list args;

        va_start(args, fmt);
        pos += vsnprintf(buf + pos, sizeof(buf) - pos, fmt, args);
        va_end(args);
}

void debug_flush()
{
	if (pos > 0 && pos < sizeof(buf) && buf[pos - 1] != '\n')
		buf[pos++] = '\n';

	if (write(STDERR_FILENO, buf, pos) < 0)
		;
	pos = 0;
}

#endif
