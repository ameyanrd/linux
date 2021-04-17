/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * PDM - IPv6 Performance and Diagnostic Metrics Destination Option
 *
 * This is an implementation of the PDM protocol as mentioned in
 * RFC 8250.
 *
 * Author: Ameya Deshpande <ameyanrd@gmail.com>
 */

#ifndef _PDM_H
#define _PDM_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/hashtable.h>

#define IP6_PDM_DEFAULT_MODE	0
#define IP6_PDM_DEFAULT_VERSION	2
#define IP6_PDM_DEFAULT_ENCRYPT	0

struct ipv6_destopt_pdm {
	u8 type;
	u8 length;
	u16 vrsnRsrvdBits;
	u16 randomNumF;
	u8 scaleDTLR;	/* Scale Delta Time Last Recieved */
	u8 scaleDTLS;	/* Scale Delta Time Last Sent */
	u32 globalPtr;
	u16 PSNTP;	/* Packet Sequence Number This Packet */
	u16 PSNLR;	/* Packet Sequence Number Last Received */
	u16 DTLR;	/* Delta Time Last Received */
	u16 DTLS;	/* Delta Time Last Sent */
};

/*
 * TODO: Check what the bits must be set as default
 */
extern DECLARE_HASHTABLE(data_hash, 8);

struct pdm_state {
	u32 key;

	u16 PSNTP;
	u16 PSNLR;

	/* 5-tuple */
	struct  in6_addr  saddr;
	struct  in6_addr  daddr;
	u16 sport;
	u16 dport;
	u8 proto;
	u16 icmp_id;

	bool sent_once;
	bool received_once;

	struct timespec64 last_received;
	struct timespec64 last_sent;

	struct hlist_node node;
};

struct pdm_state* get_state(struct sk_buff *skb, bool is_received, struct net *net, struct flowi6 *fl6);

#endif	/* _PDM_H */
