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

#ifndef __NETNS_H
#define __NETNS_H

void init_netns(void);

int switch_ns(int nsfd, sigset_t *oldmask);
void restore_ns(sigset_t *oldmask);

int open_ns(int nsfd, const char *pathname, int flags);
int socket_ns(int nsfd, int domain, int type, int protocol);
int get_nsfd(const char *name);

#endif
