# l2tp-nfqd - netfilter NFQUEUE helper for L2TP

<code>l2tp-nfqd</code> is *not* an L2TP daemon. It can be used in combination with a Linux L2TP/IPSec VPN server to support multiple L2TP clients behind IPv4 NAT.

<code>l2tp-nfqd</code> listens on a netfilter NFQUEUE for L2TPv2 tunnel setup messages and posts IPC messages containing information about the L2TP tunnel and the netfilter connmark assigned by Strongswan/Libreswan. An L2TP daemon can use this to learn the connmark associated with each L2TP tunnel such that it can set the tunnel socket's <code>SO_MARK</code> to match. In this way, packet flows between two or more peers can be distinguished even if they use the same UDP ports.

## How to build

<code>l2tp-nfqd</code> uses <code>libnetfilter_queue</code>.

    apt-get install libnetfilter-queue-dev
	./bootstrap
	./configure
    make install

## How to use

First, configure netfilter to queue received L2TPv2 messages to an NFQUEUE. It is important that this matches only L2TPv2 control messages with TID 0, hence the netfilter <code>xt_l2tp</code> filter is used. Although <code>l2tp-nfqd</code> will ignore other messages if they are pushed to NFQUEUE, for efficiency it is better that netfilter matches only these packets. 

    modprobe xt_l2tp
    iptables -t mangle -A INPUT -p udp -m udp --dport 1701 \
      -m l2tp --tid 0 --pversion 2 --type control \
      -m policy --dir in --pol ipsec --strict --proto esp \
      -j NFQUEUE --queue-num 1 --queue-bypass

Configure Strongswan with *connmark* enabled for L2TP/IPSec connections. See https://wiki.strongswan.org/projects/strongswan/wiki/Connmark

Run <code>l2tp-nfqd</code> with arguments to tell it which NFQUEUE to read and the pathname of the socket to write when L2TP messages arrive on the NFQUEUE.

    l2tp-nfqd -n 1 -o /path/to/nfq-sock
 
Run an L2TP daemon which is built with support for <code>l2tp-nfqd</code>. The L2TP daemon should listen on messages arriving on <code>/path/to/nfq-sock</code> and process them, e.g.:

    #include <l2tp-nfq/l2tp-nfqd.h>

	struct l2tp_nfq_msg buf;
    struct sockaddr_un s = {
        .sun_family = AF_UNIX,
		.sun_path = "/path/to/nfq-sock",
    };
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    bind(fd, (const struct sockaddr *) &s, sizeof(struct sockaddr_un));
    recv(fd, &buf, sizeof(buf), 0);

On receipt of a message from <code>l2tp-nfqd</code>, the L2TP daemon should record the indicated peer IP address, peer tunnel ID and mark values in order to match these with incoming SCCRQ messages and its associated L2TP tunnel instance. The L2TP daemon should assign the indicated mark to the tunnel's UDP socket using <code>setsockopt(SO_MARK)</code>.
