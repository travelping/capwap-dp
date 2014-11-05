#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _REENTRANT

#include <assert.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <ev.h>

#include "erl_interface.h"
#include "ei.h"

#include "capwap-dp.h"

static const char _ident[] = "capwap-dp v" VERSION;
static const char _build[] = "build on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

struct controller {
	LIST_ENTRY(controller) controllers;

	int fd;
	ErlConnect conp;

	ev_io ev_read;
	// write_lock
};

LIST_HEAD(controllers, controller) controllers = LIST_HEAD_INITIALIZER(controllers);
static ei_cnode ec;

static void async_reply(int fd, ETERM *from, ETERM *resp)
{
	ETERM *pid, *m;
	ETERM *marr[2];

	pid = erl_element(1, from);

	/* M = {Tag, Msg} */
	marr[0] = erl_element(2, from);  /* Tag */
	marr[1] = resp;
	m = erl_mk_tuple(marr, 2);

	erl_send(fd, pid, m);
}

static void handle_gen_call(int fd, const char *to, ETERM *from, ETERM *tuple)
{
	ETERM *fn;

	fn = erl_element(1, tuple);

	if (strncmp(to, "net_kernel", 10) == 0 &&
	    strncmp(ERL_ATOM_PTR(fn), "is_auth", 7) == 0) {
		async_reply(fd, from, erl_mk_atom("yes"));
	}

	erl_free_term(fn);
}

static void handle_gen_cast(int fd, ETERM *cast)
{
}

static void erl_read_cb(EV_P_ ev_io *w, int revents)
{
	ei_x_buff x;
	erlang_msg msg;
	int r;

	ei_x_new(&x);
	r = ei_xreceive_msg(w->fd, &msg, &x);
	if (r == ERL_TICK) {
		/* ignore */
	} else if (r == ERL_ERROR) {
		fprintf(stderr, "ERROR on fd %d, %s (%d)\n", w->fd, strerror(erl_errno), erl_errno);
		close(w->fd);
		ev_io_stop (EV_A_ w);
	} else {
		int index = 0;

		switch (msg.msgtype) {
		case ERL_REG_SEND: {
			ETERM *fmsg, *type;

			ei_decode_term(x.buff, &index, &fmsg);
			type = erl_element(1, fmsg);

			fprintf(stderr, "Msg to: %s, ", msg.toname);
			erl_print_term(stderr, fmsg);
			fprintf(stderr, "\n");

			if (strncmp(ERL_ATOM_PTR(type), "$gen_call", 9) == 0) {
				ETERM *from, *call;

				from = erl_element(2, fmsg);
				call = erl_element(3, fmsg);
				handle_gen_call(w->fd, msg.toname, from, call);
				erl_free_term(from);
				erl_free_term(call);
			}
			else if (strncmp(ERL_ATOM_PTR(type), "$gen_cast", 9) == 0) {
				ETERM *cast;

				cast = erl_element(2, fmsg);
				handle_gen_cast(w->fd, cast);
				erl_free_term(cast);
			}

			erl_free_term(type);
			erl_free_term(fmsg);

			break;
		}
		default:
			fprintf(stderr, "msg.msgtype: %ld\n", msg.msgtype);
			break;
		}
	}

	ei_x_free(&x);
}

static void listen_cb(EV_P_ ev_io *w, int revents)
{
	struct controller *cnt;

	if (!(cnt = malloc(sizeof(struct controller))))
		return;
	memset(cnt, 0, sizeof(struct controller));

	if ((cnt->fd = ei_accept_tmo(&ec, w->fd, &cnt->conp, 100)) == ERL_ERROR) {
		fprintf(stderr, "Failed to ei_accept on fd %d with %s (%d)\n", w->fd, strerror(erl_errno), erl_errno);
		free(cnt);
		return;
	}

	fprintf(stderr, "ei_accept, got fd %d (%d)\n", cnt->fd, erl_errno);

	ev_io_init(&cnt->ev_read, erl_read_cb, cnt->fd, EV_READ);
	ev_io_start(EV_A_ &cnt->ev_read);

	LIST_INSERT_HEAD(&controllers, cnt, controllers);
}

static void usage(void)
{
        printf("TPLINO CAPWAP Data Path Deamon, Version: .....\n\n"
               "Usage: capwap-dp [OPTION...]\n\n"
               "Options:\n\n"
               "  -h                        this help\n"
               "  -p, --port=PORT           bind proxy to port (default 3128)\n"
               "  -i, --bind=IP             bind proxy to IP\n"
               "                            forwarded to this netblock\n\n");

        exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
        const struct rlimit rlim = {
                .rlim_cur = RLIM_INFINITY,
                .rlim_max = RLIM_INFINITY
        };
        struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_ANY)
	};
	struct ev_loop *loop = EV_DEFAULT;
	int on = 1;

        int c;
	socklen_t slen;
	int listen_fd;
	ev_io listen_ev;

        /* unlimited size for cores */
        setrlimit(RLIMIT_CORE, &rlim);

        while (1) {
                int option_index = 0;
                static struct option long_options[] = {
                        {"port",      1, 0, 'p'},
                        {"bind",      1, 0, 'i'},
                        {0, 0, 0, 0}
                };

                c = getopt_long(argc, argv, "hi:p:",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'h':
                        usage();
                        break;

                case 'i':
                        if (inet_aton(optarg, &addr.sin_addr) == 0) {
                                fprintf(stderr, "Invalid IP address: '%s'\n", optarg);
                                exit(EXIT_FAILURE);
                        }
                        break;

                case 'p':
                        addr.sin_port = htons(strtol(optarg, NULL, 0));
                        if (errno != 0) {
                                fprintf(stderr, "Invalid numeric argument: '%s'\n", optarg);
                                exit(EXIT_FAILURE);
                        }
                        break;

                default:
                        printf("?? getopt returned character code 0%o ??\n", c);
                }
        }

	erl_init(NULL, 0);

	if ((listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) < 0)
		exit(EXIT_FAILURE);

	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("error bind: %m\n");
		exit(EXIT_FAILURE);
	}

	slen = sizeof(addr);
	if (getsockname(listen_fd, (struct sockaddr *)&addr, &slen) < 0) {
		printf("error getsockname: %m\n");
		exit(EXIT_FAILURE);
	}

	if (ei_connect_init(&ec, "capwap-dp", "cookie", 0) < 0) {
		fprintf(stderr,"ERROR when initializing: %d",erl_errno);
		exit(EXIT_FAILURE);
	}

	if (ei_publish(&ec, ntohs(addr.sin_port)) < 0) {
		fprintf(stderr,"unable to register with EPMD: %d", erl_errno);
		exit(EXIT_FAILURE);
	}

	listen(listen_fd, 5);

	ev_io_init(&listen_ev, listen_cb, listen_fd, EV_READ);
	ev_io_start(loop, &listen_ev);

	for (int i = 0; i < 10; i++)
		start_worker(i);

	printf("starting loop\n");
	ev_run(loop, 0);

        return 0;
}
