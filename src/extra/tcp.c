/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Vyatta Inc. <http://www.vyatta.com>
 */

#include <stdio.h>
#include <string.h> /* for memcpy */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>

#include "internal.h"

/**
 * \defgroup tcp TCP helper functions
 * @{
 */

/**
 * nfq_tcp_get - get the TCP header
 * \param pktb: pointer to user-space network packet buffer
 *
 * This function returns NULL if an invalid TCP header is found. On success,
 * it returns the TCP header.
 *
 * \note You have to call nfq_ip_set_transport_header or
 * nfq_ip6_set_transport_header first to access the TCP header.
 */
struct tcphdr *nfq_tcp_get_hdr(struct pkt_buff *pktb)
{
	if (pktb->transport_header == NULL)
		return NULL;

	/* No room for the TCP header. */
	if (pktb->tail - pktb->transport_header < sizeof(struct tcphdr))
		return NULL;

	return (struct tcphdr *)pktb->transport_header;
}
EXPORT_SYMBOL(nfq_tcp_get_hdr);

/**
 * nfq_tcp_get_payload - get the TCP packet payload
 * \param tcph: pointer to the TCP header
 * \param pktb: pointer to user-space network packet buffer
 */
void *nfq_tcp_get_payload(struct tcphdr *tcph, struct pkt_buff *pktb)
{
	unsigned int doff = tcph->doff * 4;

	/* malformed TCP data offset. */
	if (pktb->transport_header + doff >= pktb->tail)
		return NULL;

	return pktb->transport_header + doff;
}
EXPORT_SYMBOL(nfq_tcp_get_payload);

/**
 * nfq_tcp_get_payload_len - get the tcp packet payload
 * \param tcph: pointer to the TCP header
 * \param pktb: pointer to user-space network packet buffer
 */
unsigned int
nfq_tcp_get_payload_len(struct tcphdr *tcph, struct pkt_buff *pktb)
{
	return pktb->tail - pktb->transport_header;
}
EXPORT_SYMBOL(nfq_tcp_get_payload_len);

/**
 * nfq_tcp_set_checksum_ipv4 - computes IPv4/TCP packet checksum
 * \param tcph: pointer to the TCP header
 * \param iph: pointer to the IPv4 header
 */
void
nfq_tcp_compute_checksum_ipv4(struct tcphdr *tcph, struct iphdr *iph)
{
	/* checksum field in header needs to be zero for calculation. */
	tcph->check = 0;
	tcph->check = checksum_tcpudp_ipv4(iph);
}
EXPORT_SYMBOL(nfq_tcp_compute_checksum_ipv4);

/**
 * nfq_tcp_set_checksum_ipv6 - computes IPv6/TCP packet checksum
 * \param tcph: pointer to the TCP header
 * \param iph: pointer to the IPv6 header
 */
void
nfq_tcp_compute_checksum_ipv6(struct tcphdr *tcph, struct ip6_hdr *ip6h)
{
	/* checksum field in header needs to be zero for calculation. */
	tcph->check = 0;
	tcph->check = checksum_tcpudp_ipv6(ip6h, tcph);
}
EXPORT_SYMBOL(nfq_tcp_compute_checksum_ipv6);

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr {
	struct tcphdr hdr;
	uint32_t  words[5];
};

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words[3])

/**
 * nfq_pkt_snprintf_tcp_hdr - print tcp header into one buffer in a humnan
 * readable way
 * \param buf: pointer to buffer that is used to print the object
 * \param size: size of the buffer (or remaining room in it).
 * \param tcp: pointer to a valid tcp header.
 *
 */
int nfq_tcp_snprintf(char *buf, size_t size, const struct tcphdr *tcph)
{
	int ret, len = 0;

#define TCP_RESERVED_BITS htonl(0x0F000000)

	ret = snprintf(buf, size, "SPT=%u DPT=%u SEQ=%u ACK=%u "
				   "WINDOW=%u RES=%0x%02x ",
			ntohs(tcph->source), ntohs(tcph->dest),
			ntohl(tcph->seq), ntohl(tcph->ack_seq),
			ntohs(tcph->window),
			(uint8_t)(ntohl(tcp_flag_word(tcph) &
				TCP_RESERVED_BITS) >> 22));
	len += ret;

	if (tcph->urg) {
		ret = snprintf(buf+len, size-len, "URG ");
		len += ret;
	}
	if (tcph->ack) {
		ret = snprintf(buf+len, size-len, "ACK ");
		len += ret;
	}
	if (tcph->psh) {
		ret = snprintf(buf+len, size-len, "PSH ");
		len += ret;
	}
	if (tcph->rst) {
		ret = snprintf(buf+len, size-len, "RST ");
		len += ret;
	}
	if (tcph->syn) {
		ret = snprintf(buf+len, size-len, "SYN ");
		len += ret;
	}
	if (tcph->fin) {
		ret = snprintf(buf+len, size-len, "FIN ");
		len += ret;
	}
	/* Not TCP options implemented yet, sorry. */
}
EXPORT_SYMBOL(nfq_tcp_snprintf);

/* XXX remove this */
#include <stdio.h>
#define pr_debug printf

/* Frobs data inside this packet, which is linear. */
static void mangle_contents(struct pkt_buff *pkt,
			    unsigned int dataoff,
			    unsigned int match_offset,
			    unsigned int match_len,
			    const char *rep_buffer,
			    unsigned int rep_len)
{
	unsigned char *data;
	struct iphdr *iph = (struct iphdr *)(pkt->data);

	data = pkt->network_header + dataoff;

	/* move post-replacement */
	memmove(data + match_offset + rep_len,
		data + match_offset + match_len,
		pkt->tail - (pkt->network_header + dataoff +
			     match_offset + match_len));

	/* insert data from buffer */
	memcpy(data + match_offset, rep_buffer, rep_len);

	/* update pkt info */
	if (rep_len > match_len) {
		pr_debug("nf_nat_mangle_packet: Extending packet by "
			 "%u from %u bytes\n", rep_len - match_len, pkt->len);
		pktb_put(pkt, rep_len - match_len);
	} else {
		pr_debug("nf_nat_mangle_packet: Shrinking packet from "
			 "%u from %u bytes\n", match_len - rep_len, pkt->len);
		pktb_trim(pkt, pkt->len + rep_len - match_len);
	}

	/* fix IP hdr checksum information */
	iph->tot_len = htons(pkt->len);
	nfq_ip_set_checksum(pkt->network_header);
}

static int pktb_expand_tail(struct pkt_buff *pkt, int extra)
{
	/* XXX possible reallocation, fix this */
	pkt->len += extra;
	pkt->tail = pkt->tail + extra;
	return 0;
}

static int enlarge_pkt(struct pkt_buff *pkt, unsigned int extra)
{
	if (pkt->len + extra > 65535)
		return 0;

	if (pktb_expand_tail(pkt, extra - pktb_tailroom(pkt)))
		return 0;

	return 1;
}

int
nfq_tcp_mangle(struct pkt_buff *pkt,
	       unsigned int match_offset, unsigned int match_len,
	       const char *rep_buffer, unsigned int rep_len)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	if (rep_len > match_len &&
	    rep_len - match_len > pktb_tailroom(pkt) &&
	    !enlarge_pkt(pkt, rep_len - match_len))
		return 0;

	iph = (struct iphdr *)pkt->network_header;
	tcph = (struct tcphdr *)(pkt->network_header + iph->ihl*4);

	mangle_contents(pkt, iph->ihl*4 + tcph->doff*4,
			match_offset, match_len, rep_buffer, rep_len);

	nfq_tcp_compute_checksum_ipv4(tcph, iph);

	return 1;
}
EXPORT_SYMBOL(nfq_tcp_mangle);

/**
 * @}
 */
