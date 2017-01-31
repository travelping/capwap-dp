/*
 * Copyright (C) 2014-2017, Travelping GmbH <info@travelping.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

void _hexdump(const char *filename, int line, const char *func,
	      const unsigned char *data, ssize_t len)
{
	struct timeval tv;
	ssize_t i;

	gettimeofday(&tv, NULL);

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			if (i != 0)
				debug_log("\n");
			_debug_head(filename, line, func, &tv);
			debug_log("0x%08zx:  ", i);
		}
		debug_log("%02x ", data[i]);
	}
	debug_flush();
}

#endif
