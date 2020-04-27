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

/**
 * @file l2tp_nfqueue.h
 * Core nfqueue implementation.
 */

#ifndef L2TP_NFQUEUE_H
#define L2TP_NFQUEUE_H

/**
 * Opaque nfqueue listener handle.
 */
typedef struct l2tp_nfq *l2tp_nfq_t;

void l2tp_nfq_run(l2tp_nfq_t nh);

/**
 * Initialise an NFQUEUE socket listener in the istener component.
 *  @param  log_level   log level
 *  @param  nfq_num     nfq number to listen on
 *  @param  result_path path of UNIX socket to write
 *  @param  np          pointer to nfqueue handle to assign on return.
 *  @return             0 on success, negative errno otherwise.
 */
int l2tp_nfq_init(int log_level, int nfq_num, const char *result_path, l2tp_nfq_t *np);

/**
 * Clean the NFQUEUE listener resources of the listener.
 *  @param  nh         nfqueue listener handle
 */
void l2tp_nfq_cleanup(l2tp_nfq_t nh);

#endif /* L2TP_NFQUEUE_H */
