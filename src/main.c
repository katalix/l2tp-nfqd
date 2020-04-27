/*
 * (C) 2020, Katalix Systems Ltd
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation (or any later at your option)
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <l2tp-nfqd.h>

#include "l2tp_nfq.h"

struct options {
    int log_level;
    int nfq_num;
    char *result_path;
};

static int parse_args(int argc, char **argv, struct options *opts)
{
    int opt;

    while ((opt = getopt(argc, argv, "n:o:d")) != -1) {
        switch (opt) {
        case 'n':
            opts->nfq_num = atoi(optarg);
            break;
        case 'o':
            opts->result_path = optarg;
            break;
        case 'd':
            opts->log_level++;
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-n qnum] [-o out-socket-path] [-d]\n",
                    argv[0]);
            return -EINVAL;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    l2tp_nfq_t n;
    int ret;
    struct options opts = {
        .log_level = LOG_NOTICE,
    };

    ret = parse_args(argc, argv, &opts);
    if (ret) return 1;
    ret = l2tp_nfq_init(opts.log_level, opts.nfq_num, opts.result_path, &n);
    if (ret) return 1;
    l2tp_nfq_run(n);
    l2tp_nfq_cleanup(n);
    return 0;
}
