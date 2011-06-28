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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <net/if_dl.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <stdlib.h>
#include <string.h>

#define ALL_LINKLOCAL_NODES "ff02::1"

int
main(void)
{
	int sock;
	/* int val; */
	struct sockaddr_in6 sin6;
	struct nd_router_advert nra;
	struct nd_opt_prefix_info nopi;

	if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1)
		err(1, "socket");
	/* val = 1; */
	/* if (setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &val, */
	/*     sizeof(val)) == -1) */
	/* 	err(1, "setsockopt"); */
	bzero(&nra, sizeof(nra));
	nra.nd_ra_type		  = ND_ROUTER_ADVERT;
	nra.nd_ra_code		  = 0;
	nra.nd_ra_curhoplimit	  = 0;
	nra.nd_ra_router_lifetime = 0xffff;
	bzero(&nopi, sizeof(nopi));
	nopi.nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	nopi.nd_opt_pi_len = 4;
	nopi.nd_opt_pi_prefix_len = sizeof(struct in6_addr);
	nopi.nd_opt_pi_valid_time = 0xffffffff;
	/* nopi.nd_opt_pi_prefix = 0; */
	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(IPPROTO_ICMPV6);
	if (inet_pton(AF_INET6, ALL_LINKLOCAL_NODES, &sin6.sin6_addr) == -1)
		err(1, "inet_pton");
	if (sendto(sock, &nra, sizeof(nra), 0, (struct sockaddr *)&sin6,
	    sizeof(sin6)) == -1)
		err(1, "sendto");
	
	return (0);
}
