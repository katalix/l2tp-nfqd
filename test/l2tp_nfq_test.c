/*****************************************************************************
 * Copyright (C) 2004-2020 Katalix Systems Ltd
 *
 * Confidential. All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the
 * property of Katalix Systems Ltd and its suppliers, if any.  The
 * intellectual and technical concepts contained herein are
 * proprietary to Katalix Systems Ltd and its suppliers, and are
 * protected by trade secret or copyright law.  Dissemination of this
 * information or reproduction of this material is strictly forbidden
 * unless prior written permission is obtained from Katalix Systems
 * Ltd.
 *****************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>

#include <l2tp-nfqd.h>

static int log_level = LOG_NOTICE;

static void nfq_log(int level, const char *fmt, ...)
{
    if (level <= log_level) {
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
    }
}

static void handle_msg(struct l2tp_nfq_msg *msg)
{
    assert(msg);
    nfq_log(LOG_INFO, "nfq: peer=%s mark=%" PRIu32 " peer_tid=%" PRIu32,
	    inet_ntoa(msg->peer_ip), msg->mark, msg->peer_tid);
}


static void nfq_run(int fd, int max_msg_count)
{
    int ret;
    struct l2tp_nfq_msg buf;
    static int msg_count = 0;
    
    /* handle messages */
    assert(fd >= 0);
    for (;;) {
	memset(&buf, 0, sizeof(buf));
        ret = recv(fd, &buf, sizeof(buf), 0);
	nfq_log(LOG_DEBUG, "recv() returned %d errno=%d", ret, ret < 0 ? errno : 0);
        if (ret == 0) {
	    /* pipe was removed */
	    break;
        } else if (ret < 0) {
	    /* ignore all errors except socket close indicators */
	    if (errno == EBADF || errno == ENOTSOCK) break;
	    continue;
        } else if (ret == sizeof(buf)) {
	    handle_msg(&buf);
	    if (max_msg_count) {
		msg_count++;
		if (msg_count >= max_msg_count) {
		    nfq_log(LOG_DEBUG, "%d messages received", msg_count);
		    break;
		}
	    }
	}
    }
}

struct options {
    int log_level;
    char *input_path;
    int max_msg_count;
};

static int parse_args(int argc, char **argv, struct options *opts)
{
    int opt;

    while ((opt = getopt(argc, argv, "i:c:d")) != -1) {
	switch (opt) {
	case 'i':
	    opts->input_path = optarg;
	    break;
	case 'c':
	    opts->max_msg_count = atoi(optarg);
	    break;
	case 'd':
	    opts->log_level++;
	    break;
	default: /* '?' */
	    fprintf(stderr, "Usage: %s -i input-socket-path [-d]\n",
		    argv[0]);
	    return -EINVAL;
	}
    }
    if (!opts->input_path) {
	fprintf(stderr, "Usage: %s -i arg missing\n", argv[0]);
	return -EINVAL;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    int fd;
    struct options opts = {
	.log_level = LOG_NOTICE,
    };
    struct sockaddr_un s = {
	.sun_family = AF_UNIX,
    };

    ret = parse_args(argc, argv, &opts);
    if (ret) return 1;
    log_level = opts.log_level;

    strncpy(s.sun_path, opts.input_path, sizeof(s.sun_path) - 1);
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (bind(fd, (const struct sockaddr *) &s,
	     sizeof(struct sockaddr_un)) < 0) {
	close(fd);
	return 1;
    }

    nfq_log(LOG_DEBUG, "listening on %s", opts.input_path);
    nfq_run(fd, opts.max_msg_count);

    close(fd);
    return 0;
}
