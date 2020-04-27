/**
 * @file l2tp-nfqd.h
 * L2TP nfqueue listener public API.
 */

#include <stdint.h>
#include <netinet/in.h>

#ifndef L2TP_NFQD_H
#define L2TP_NFQD_H

/**
 * A message sent by l2tp-nfqd is a flat structure.
 */
struct l2tp_nfq_msg {
    uint32_t reserved;          /**< Reserved for future expansion. Must be zero */
    struct in_addr peer_ip;     /**< IPv4 address of peer */
    uint32_t peer_tid;          /**< Peer L2TP tunnel-id  */
    uint32_t mark;              /**< Netfilter mark */
};

#endif /* L2TP_NFQD_H */
