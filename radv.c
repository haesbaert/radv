/*
 * Copyright (c) 2011 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <net/if_arp.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* These must match */
#define ALL_LINKLOCAL_NODES	"FF02::1"
#define ALL_LINKLOCAL_NODES_HW	"33:33:00:00:00:01"
#define IP6_ADDRESS		"fe80::21d:e0ff:fe06:7421" 

extern char *__progname;

int
main(int argc, char *argv[])
{
	int bpf;
	struct ifreq ifreq;
	struct ether_header eh;
	struct ip6_hdr ip6;
	struct ether_addr *eha;
	struct in6_addr in6;
	struct nd_router_advert nra;
	struct nd_opt_prefix_info nopi;
	struct iovec iov[4];

	if (argc != 3)
		errx(1, "usage: %s ifname prefix6", __progname);
	bzero(&in6, sizeof(in6));
	if (inet_pton(AF_INET6, argv[2], &in6) != 1)
		errx(1, "inet_pton");
	/* Berkeley Packet Filter */
	if ((bpf = open("/dev/bpf5", O_RDWR)) == -1)
		err(1, "open");
	bzero(&ifreq, sizeof(ifreq));
	(void)strlcpy(ifreq.ifr_name, argv[1], sizeof(ifreq.ifr_name));
	if (ioctl(bpf, BIOCSETIF, &ifreq) != 0)
		err(1, "ioctl");
	/* ICMPv6 */
	bzero(&nra, sizeof(nra));
	nra.nd_ra_type		  = ND_ROUTER_ADVERT;
	nra.nd_ra_code		  = 0;
	nra.nd_ra_cksum		  = htons(0x13c7);	/* XXX */
	nra.nd_ra_curhoplimit	  = 0;
	nra.nd_ra_router_lifetime = 0xffff;
	bzero(&nopi, sizeof(nopi));
	nopi.nd_opt_pi_type	  = ND_OPT_PREFIX_INFORMATION;
	nopi.nd_opt_pi_len	  = 4;
	nopi.nd_opt_pi_prefix_len = sizeof(struct in6_addr);
	nopi.nd_opt_pi_valid_time = 0xffffffff;
	nopi.nd_opt_pi_prefix 	  = in6;
	/* IPv6 */
	bzero(&ip6, sizeof(ip6));
	ip6.ip6_vfc  = IPV6_VERSION &	IPV6_VERSION_MASK;
	ip6.ip6_nxt  = IPPROTO_ICMPV6;
	ip6.ip6_plen = htons(sizeof(nra) + sizeof(nopi));
	if (inet_pton(AF_INET6, ALL_LINKLOCAL_NODES, &ip6.ip6_dst) != 1)
		errx(1, "inet_pton");
	if (inet_pton(AF_INET6, IP6_ADDRESS, &ip6.ip6_src) != 1)
		errx(1, "inet_pton");
	/* Ethernet */
	bzero(&eh, sizeof(eh));
	eh.ether_type = htons(ETHERTYPE_IPV6);
	eha = ether_aton(ALL_LINKLOCAL_NODES_HW);
	if (eha == NULL)
		errx(1, "ether_aton");
	memcpy(eh.ether_dhost, eha, ETHER_ADDR_LEN);
	iov[0].iov_base = &eh;
	iov[0].iov_len	= sizeof(eh);
	iov[1].iov_base = &ip6;
	iov[1].iov_len	= sizeof(ip6);
	iov[2].iov_base = &nra;
	iov[2].iov_len	= sizeof(nra);
	iov[3].iov_base = &nopi;
	iov[3].iov_len	= sizeof(nopi);
	if ((writev(bpf, iov, 4)) == -1)
		err(1, "write");
	
	return (0);
}
