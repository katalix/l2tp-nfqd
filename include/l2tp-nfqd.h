/**
 * @file l2tp-nfqd.h
 * L2TP nfqueue listener public API.
 */

#include <stdint.h>
#include <netinet/in.h>

#ifndef L2TP_NFQD_H
#define L2TP_NFQD_H

/**
 * A message sent by l2tp-nfqd is a variable length, flat structure.
 */
struct l2tp_nfq_msg {
    uint16_t reserved;          /**< Reserved for future expansion. Must be 1 */
    uint16_t len;               /**< message size */
    struct in_addr peer_ip;     /**< IPv4 address of peer */
    uint32_t peer_tid;          /**< Peer L2TP tunnel-id, from SCCRQ */
    uint32_t mark;              /**< Netfilter mark */
    char hostname[];            /**< Peer Hostname, from SCCRQ */
};

#define L2TP_NFQ_MSG_MAX_SIZE (sizeof(struct l2tp_nfq_msg) + 1024)

#endif /* L2TP_NFQD_H */
