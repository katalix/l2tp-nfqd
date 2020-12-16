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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/pktbuff.h>

#include <l2tp-nfqd.h>

#include "l2tp_nfq.h"

/* The L2TPv2 control header is of variable length. The first byte
 * contains a number of flags that identify whether fields are present
 * in the header itself.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Tunnel ID           |           Session ID          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Ns              |               Nr              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Offset Size (opt)        |    Offset pad... (opt)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * We use C bitfields to represent bits in the header. We need to
 * take account of different bit-orders for little and big endian,
 * I use a macro to do that.
 */
#if (__BYTE_ORDER == __BIG_ENDIAN)
#define X(a,b)  b,a
#elif (__BYTE_ORDER == __LITTLE_ENDIAN)
#define X(a,b)  a,b
#else
#error  "Adjust your <endian.h> defines"
#endif

struct l2tp_ctl_hdr_v2 {
    union {
        struct {
            uint8_t X(X(X(X(X(X(p_bit:1, o_bit:1), rsvd_2:1), s_bit:1), rsvd_1:2), l_bit:1), t_bit:1);
            uint8_t X(ver:4, rsvd_3:4);
        };
        uint16_t flags_ver;
    };
    uint16_t    length;
    uint16_t    tunnel_id;
    uint16_t    session_id;
    uint16_t    ns;
    uint16_t    nr;
    uint8_t     data[0];
};

#undef X

#define l2tp_ctl_hdr_length(_buf)   ( ((struct l2tp_ctl_hdr_v2 *)(_buf))->length )
#define l2tp_ctl_hdr_version(_buf)  ( ((struct l2tp_ctl_hdr_v2 *)(_buf))->ver )
#define l2tp_ctl_hdr_t_bit(_buf)    ( ((struct l2tp_ctl_hdr_v2 *)(_buf))->t_bit )
#define l2tp_ctl_hdr_o_bit(_buf)    ( ((struct l2tp_ctl_hdr_v2 *)(_buf))->o_bit )

#define L2TP_AVP_HEADER_LEN         6
#define L2TP_AVP_MAX_LEN            1024

#define L2TP_AVP_VENDOR_IETF        0

#define L2TP_AVP_MSG_SCCRQ          1
#define L2TP_AVP_TYPE_MESSAGE       0
#define L2TP_AVP_TYPE_HOSTNAME      7
#define L2TP_AVP_TYPE_TUNNEL_ID     9

struct l2tp_avp_hdr {
    uint16_t    flag_len;
#define L2TP_AVP_HDR_MBIT           0x8000
#define L2TP_AVP_HDR_HBIT           0x4000
#define L2TP_AVP_HDR_LEN(_flag_len)     ((_flag_len) & 0x03ff)
#define L2TP_AVP_HDR_FLAGS(_flag_len)   ((_flag_len) & 0xfc00)
    uint16_t    vendor_id;
    uint16_t    type;
    uint8_t     value[0];       /* variable length */
} __attribute__((packed));

struct l2tp_nfq {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    const char *result_path;
    int nfq_num;
    int log_level;
    int out_fd;
    char buf[4096] __attribute__ ((aligned));
};

static void nfq_log(struct l2tp_nfq *n, int level, const char *fmt, ...)
{
    if (level <= n->log_level) {
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        printf("\n");
        fflush(stdout);
        va_end(ap);
    }
}

static bool get_peer_info(struct l2tp_nfq *n, void *data, size_t nbytes, struct l2tp_nfq_msg *msg)
{
    struct l2tp_avp_hdr *avp = data;
    uint16_t msg_type = 0;

    if (nbytes < L2TP_AVP_HEADER_LEN) return false;

    nfq_log(n, LOG_DEBUG, "first avp: type=%hu vendor=%hu",
            ntohs(avp->type), ntohs(avp->vendor_id));

    /* First AVP must be MESSAGE_TYPE */
    if ((ntohs(avp->type) != L2TP_AVP_TYPE_MESSAGE) ||
        (ntohs(avp->vendor_id) != L2TP_AVP_VENDOR_IETF)) {
        return false;
    }

    msg->peer_tid = 0;
    msg->hostname[0] = '\0';
    msg->len = sizeof(*msg);
    while (nbytes >= L2TP_AVP_HEADER_LEN) {
        uint16_t avp_type = ntohs(avp->type);
        uint16_t avp_vendor_id = ntohs(avp->vendor_id);
        uint16_t avp_flaglen = ntohs(avp->flag_len);
        size_t avp_len = L2TP_AVP_HDR_LEN(avp_flaglen);

        nfq_log(n, LOG_DEBUG, "avp: type=%hu vendor=%hu len=%Zu",
                avp_type, avp_vendor_id, avp_len);
        if (avp_len < L2TP_AVP_HEADER_LEN || avp_len >= 1024 || avp_len > nbytes) {
            return false;
        }
        if ((avp_type == L2TP_AVP_TYPE_MESSAGE) &&
            (avp_vendor_id == L2TP_AVP_VENDOR_IETF)) {
            uint16_t *val16;
            if (L2TP_AVP_HDR_FLAGS(avp_flaglen) & L2TP_AVP_HDR_HBIT) return false;
            if (avp_len != (L2TP_AVP_HEADER_LEN + sizeof(uint16_t))) return false;
            val16 = (uint16_t *) &avp->value[0];
            msg_type = ntohs(*val16);
            if (msg_type != L2TP_AVP_MSG_SCCRQ) return false;
        } else if ((avp_type == L2TP_AVP_TYPE_TUNNEL_ID) &&
                   (avp_vendor_id == L2TP_AVP_VENDOR_IETF)) {
            uint16_t *val16;
            if (L2TP_AVP_HDR_FLAGS(avp_flaglen) & L2TP_AVP_HDR_HBIT) return false;
            if (avp_len != (L2TP_AVP_HEADER_LEN + sizeof(uint16_t))) return false;
            val16 = (uint16_t *) &avp->value[0];
            if (0 == msg->peer_tid) {
                msg->peer_tid = ntohs(*val16);
            }
        } else if ((avp_type == L2TP_AVP_TYPE_HOSTNAME) &&
                   (avp_vendor_id == L2TP_AVP_VENDOR_IETF)) {
            if (L2TP_AVP_HDR_FLAGS(avp_flaglen) & L2TP_AVP_HDR_HBIT) return false;
            if (avp_len <= L2TP_AVP_HEADER_LEN) return false;
            if (!msg->hostname[0]) {
                memcpy(&msg->hostname[0], &avp->value[0], avp_len - L2TP_AVP_HEADER_LEN);
                msg->hostname[avp_len - L2TP_AVP_HEADER_LEN] = '\0';
                msg->len += (avp_len - L2TP_AVP_HEADER_LEN);
            }
        }

        if (msg_type && msg->peer_tid && msg->hostname[0]) return true;

        avp = (struct l2tp_avp_hdr *)(((char*)avp) + avp_len);
        nbytes -= avp_len;
    }
    /* if we get here, MESSAGE_TYPE, TUNNEL_ID or HOSTNAME AVP is missing */
    return false;
}

static void output(struct l2tp_nfq *n, struct l2tp_nfq_msg *msg)
{
    assert(n);
    assert(msg);

    /* if no result_path, output is not required */
    if (!n->result_path) return;

    /* If output pipe not yet opened, open it now before sending the
     * message. If the pipe cannot be opened, there's no point sending
     * the message.
     */
    if (n->out_fd < 0) {
        struct sockaddr_un s = {
            .sun_family = AF_UNIX,
        };
        int fd;
        strncpy(s.sun_path, n->result_path, sizeof(s.sun_path) - 1);
        fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd < 0) {
            return;
        }
        if (connect(fd, (const struct sockaddr *) &s,
                    sizeof(struct sockaddr_un)) < 0) {
            close(fd);
            return;
        }
        n->out_fd = fd;
        nfq_log(n, LOG_INFO, "nfqueue: opened '%s' for writing",
                n->result_path);
        /* recurse! */
        output(n, msg);
    } else {
        ssize_t nb = send(n->out_fd, msg, msg->len, MSG_EOR | MSG_WAITALL | MSG_NOSIGNAL);
        if (nb <= 0) {
            nfq_log(n, LOG_INFO, "nfqueue: closed '%s'", n->result_path);
            close(n->out_fd);
            n->out_fd = -1;
        }
    }
}

static void handle_pkt(struct nfq_data *tb, struct l2tp_nfq *n)
{
    char msg_buf[L2TP_NFQ_MSG_MAX_SIZE];
    struct l2tp_nfq_msg *msg = (void *) &msg_buf[0];
    uint32_t mark = nfq_get_nfmark(tb);
    
    if (mark) {
        int len;
        unsigned char *data;
        struct pkt_buff *pb;
        struct iphdr *ip;
        len = nfq_get_payload(tb, &data);
        if (len < sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct l2tp_ctl_hdr_v2)) return;
        pb = pktb_alloc(AF_INET, data, len, 0);
        if (!pb) return;
        ip = nfq_ip_get_hdr(pb);
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp;
            struct l2tp_ctl_hdr_v2 *lh;
            memset(msg, 0, sizeof(*msg));
            msg->hostname[0] = '\0';
            msg->reserved = 1;
            msg->len = sizeof(*msg);
            msg->mark = mark;
            msg->peer_ip.s_addr = ip->saddr;
            nfq_ip_set_transport_header(pb, ip);
            udp = nfq_udp_get_hdr(pb);
            lh = (void *)(udp + 1);
            if (l2tp_ctl_hdr_version(lh) != 2) return; /* l2tpv2 */
            if (!l2tp_ctl_hdr_t_bit(lh)) return;       /* control packet */
            if (l2tp_ctl_hdr_o_bit(lh)) return;        /* offset unsupported */
            if (lh->tunnel_id) return;                 /* TID=0 for SCCRQ */
            if (lh->session_id) return;                /* SID=0 for SCCRQ */
            if (lh->ns) return;                        /* NS=0 for SCCRQ */
            if (lh->nr) return;                        /* NR=0 for SCCRQ */
            len = data + len - &lh->data[0];
            data = &lh->data[0];
            if (!get_peer_info(n, data, len, msg)) return; /* not SCCRQ or required AVPs missing */
            nfq_log(n, LOG_INFO, "nfqueue: L2TPv2 SCCRQ from %s, TID %" PRIu32
                    " hostname '%s' mark %" PRIu32,
                    inet_ntoa(msg->peer_ip), msg->peer_tid, msg->hostname, msg->mark);
            output(n, msg);
        }
        pktb_free(pb);
    }
}

static int l2tp_nfq_msg_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                           struct nfq_data *nfa, void *dptr)
{
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        uint32_t id = ntohl(ph->packet_id);
        struct l2tp_nfq *n = dptr;
        if (ntohs(ph->hw_protocol) == 0x0800 /* IPv4 */) {
            handle_pkt(nfa, n);
        }
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    return -1;
}

void l2tp_nfq_run(l2tp_nfq_t nh)
{
    struct l2tp_nfq *n = nh;
    int ret;
    int fd;

    assert(n);

    /* handle messages */
    fd = nfq_fd(n->h);
    assert(fd >= 0);
    for (;;) {
        ret = recv(fd, n->buf, sizeof(n->buf), 0);
        if (ret == 0) {
            /* NFQUEUE was removed */
            break;
        } else if (ret < 0) {
            /* ignore all errors except socket close indicators */
            if (errno == EBADF || errno == ENOTSOCK) break;
            continue;
        }
        nfq_handle_packet(n->h, n->buf, ret);
    }
}

int l2tp_nfq_init(int log_level, int nfq_num, const char *result_path,
                  l2tp_nfq_t *np)
{
    struct l2tp_nfq *n;
    int fd;
    int ret = -EFAULT;

    if (!np || nfq_num < 0) return -EINVAL;

    n = calloc(1, sizeof(*n));
    if (!n) return -ENOMEM;

    n->log_level = log_level;
    n->nfq_num = nfq_num;
    n->result_path = result_path;
    n->out_fd = -1;

    /* error paths may set and use errno values */
    errno = 0;
    nfq_errno = 0;

    n->h = nfq_open();
    if (!n->h) goto out;

    /* unbinding existing nf_queue handler for AF_INET (if any) */
    if (nfq_unbind_pf(n->h, AF_INET) < 0) goto out;
    if (nfq_bind_pf(n->h, AF_INET) < 0) goto out;

    n->qh = nfq_create_queue(n->h, nfq_num, l2tp_nfq_msg_cb, n);
    if (!n->qh) goto out;

    /* set copy_packet mode so that packet payload is copied to us */
    if (nfq_set_mode(n->qh, NFQNL_COPY_PACKET, 0xffff) < 0) goto out;

    /* Some kernels don't support these flags so ignore any errors */
    (void) nfq_set_queue_flags(n->qh, NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO,
                               NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO);

    /* disable ENOBUFS error on socket full */
    fd = nfq_fd(n->h);
    if (fd >= 0) {
        int on = 1;
        ret = setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(on));
        if (ret) goto out;
    } else {
        ret = -ENODEV;
    }

  out:
    if (ret) {
        if (nfq_errno) ret = -nfq_errno;
        else if (errno) ret = -errno;
        nfq_log(n, LOG_ERR, "failed to setup NFQUEUE queue %d: %s",
                nfq_num, strerror(-ret));
        l2tp_nfq_cleanup(n);
    } else {
        nfq_log(n, LOG_INFO, "listening on NFQUEUE queue %d", nfq_num);
        *np = n;
    }

    return ret;
}

void l2tp_nfq_cleanup(l2tp_nfq_t nh)
{
    struct l2tp_nfq *n = nh;

    nfq_log(n, LOG_INFO, "unbinding from NFQUEUE queue %d", n->nfq_num);
    if (n->qh) {
        nfq_destroy_queue(n->qh);
    }
    if (n->h) {
        nfq_close(n->h);
    }
    if (n->out_fd >= 0) {
        close(n->out_fd);
    }
    free(n);
}
