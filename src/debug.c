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

#include "debug.h"

#if !defined(NDEBUG)

__thread char buf[4069];
__thread size_t pos = 0;

void debug_log(const char *fmt, ...)
{
	ssize_t l;
        va_list args;

        va_start(args, fmt);
        l = vsnprintf(buf + pos, sizeof(buf) - pos, fmt, args);
        va_end(args);

	if (l > 0)
		pos += l;
}

void debug_flush()
{
	if (write(STDERR_FILENO, buf, pos) < 0)
		;
	pos = 0;
}

#endif
