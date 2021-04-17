/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * PDM - IPv6 Performance and Diagnostic Metrics Destination Option
 *
 * This is an implementation of the PDM protocol as mentioned in
 * RFC 8250.
 *
 * Author: Ameya Deshpande <ameyanrd@gmail.com>
 */


#include <linux/errno.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/pdm.h>
#include <linux/random.h>
#include <net/ipv6.h>
//#include <net/xfrm.h>
#include <net/pdm.h>

#include <linux/math.h>

/* Size of the PDM option including
 * the two-byte TLV header.
 */
#define PDMV2_UNENC_HDR_LEN	(2 + 18)
#define PDMV2_ENC_HDR_LEN	(2 + 34)

DECLARE_HASHTABLE(data_hash, 8);

struct pdm_state* state_add(struct sk_buff *skb, struct flow_keys *fl_keys, u32 key, bool is_received)
{
	struct pdm_state *state;

	state = kzalloc (sizeof (*state), GFP_KERNEL);
	pr_info ("state add called once!!!");

	state->key = key;
	if (!is_received)
	{
		state->PSNTP = (u16)(get_random_u32 () >> 16);
		state->PSNLR = 0;
		ktime_get_ts64 (&(state->last_sent));
	}

	pr_info ("last_sent time = %ld\n", (state->last_sent).tv_nsec);

	state->saddr = fl_keys->addrs.v6addrs.src;
	state->daddr = fl_keys->addrs.v6addrs.dst;
	state->sport = fl_keys->ports.src;
	state->dport = fl_keys->ports.dst;
	state->icmp_id = fl_keys->icmp.id;

	if (is_received)
	{
		state->sent_once = false;
		state->received_once = true;
	}
	else
	{
		state->sent_once = true;
		state->received_once = false;
	}

	state->proto = fl_keys->basic.ip_proto;

	hash_add (data_hash, &state->node, key);

	pr_info("Inside add_state = %d\n", state->PSNTP);

	return state;
}

struct pdm_state* get_state(struct sk_buff *skb, bool is_received, struct net *net, struct flowi6 *fl6)
{
	struct pdm_state *state;
	struct flow_keys hash_keys, fl_keys;
	u32 key;
	int thoff = skb_transport_offset(skb);

	memset(&fl_keys, 0, sizeof(fl_keys));
	fl_keys.control.addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;

	if (!is_received)
	{
		if (fl6)
		{
			memcpy(&fl_keys.addrs.v6addrs.src, &fl6->saddr,
	    		   sizeof(fl_keys.addrs.v6addrs.src));
			memcpy(&fl_keys.addrs.v6addrs.dst, &fl6->daddr,
	    		   sizeof(fl_keys.addrs.v6addrs.dst));
			fl_keys.basic.ip_proto = fl6->flowi6_proto;
			if (fl_keys.basic.ip_proto != IPPROTO_ICMPV6)
			{
				fl_keys.ports.src = fl6->fl6_sport;
				fl_keys.ports.dst = fl6->fl6_dport;
			}
		}
	}
	else
	{
		unsigned int flag = FLOW_DISSECTOR_F_STOP_AT_ENCAP;
		struct flow_keys keys;
		skb_flow_dissect_flow_keys(skb, &keys, flag);
		memcpy(&fl_keys.addrs.v6addrs.src, &keys.addrs.v6addrs.dst,
			   sizeof(fl_keys.addrs.v6addrs.src));
		memcpy(&fl_keys.addrs.v6addrs.dst, &keys.addrs.v6addrs.src,
			   sizeof(fl_keys.addrs.v6addrs.dst));
		fl_keys.basic.ip_proto = keys.basic.ip_proto;
		if (fl_keys.basic.ip_proto != IPPROTO_ICMPV6)
		{
			fl_keys.ports.src = keys.ports.dst;
			fl_keys.ports.dst = keys.ports.src;
		}
		if (!net->ipv6.sysctl.pdm_encrypt)
			thoff += 24;
		else
			thoff += 40;
	}

	/* TODO: How to handle ICMP traffic in a better way? */
	if (fl_keys.basic.ip_proto == IPPROTO_ICMPV6)
	{
		skb_flow_get_icmp_tci(skb, &fl_keys.icmp, skb->data,
							  thoff, skb_headlen(skb));
		fl_keys.icmp.type = 0;
		fl_keys.icmp.code = 0;
	}

	memcpy(&hash_keys, &fl_keys, sizeof(fl_keys));
	key = flow_hash_from_keys(&hash_keys);
	pr_info("Hash: %u\n", key);

	hash_for_each_possible(data_hash, state, node, key)
	{
		if ((state->proto == fl_keys.basic.ip_proto) &&
			(state->sport == fl_keys.ports.src) &&
			(state->dport == fl_keys.ports.dst) &&
			(state->icmp_id == fl_keys.icmp.id) &&
			ipv6_addr_equal(&state->saddr, &fl_keys.addrs.v6addrs.src) &&
			ipv6_addr_equal(&state->daddr, &fl_keys.addrs.v6addrs.dst))
		{
			return state;
		}
	}

	/* If not found, create a new one */
	return state_add (skb, &fl_keys, key, is_received);
}

void pdm_time_delta_scale (long int time_diff, u16 *delta, u8 *scale)
{
	int index = 0;
	long int base = time_diff;
	if (time_diff > 65535) {
		index = roundup (ilog2 (base / 65535), 1);
		base = base / (1 << index);
	}
	*scale = index + 14;
	base *= 61035;
	if (base > 65535) {
		index = roundup (ilog2 (base / 65535), 1);
		base /= (1 << index);
	}
	*scale += index;
	*delta = base;
}

void pdm_genopt(struct sk_buff *skb, unsigned char *buf, struct net *net, struct flowi6 *fl6)
{
	struct pdm_state *state;
	struct ipv6hdr *hdr;
	u16 DTLR, DTLS;
	u8 scaleDTLR, scaleDTLS;
	long int diff1, diff2;
	int scope;
	static u_int32_t global_ptr_g =		0;
	static u_int32_t global_ptr_ll =	0;

	hdr = ipv6_hdr(skb);
	scope = ipv6_addr_scope(&hdr->saddr);

	pr_info ("pdm_genopt global_ptr_g = %u\n", global_ptr_g);
	pr_info ("pdm_genopt global_ptr_ll = %u\n", global_ptr_ll);

	state = get_state (skb, false, net, fl6);

	if (!state->sent_once)
	{
		state->PSNTP = (u16)(get_random_u32 () >> 16);
		state->sent_once = true;
	}

	buf[0] = IPV6_TLV_PDM;
	if (!net->ipv6.sysctl.pdm_encrypt)
		buf[1] = PDMV2_UNENC_HDR_LEN - 2;
	else
		buf[1] = PDMV2_ENC_HDR_LEN - 2;
	buf[2] = 32;
	if (scope == IPV6_ADDR_SCOPE_GLOBAL)
	{
		*(__be32 *)(buf + 8) = htonl(global_ptr_g);
		global_ptr_g++;
	}
	else if (scope == IPV6_ADDR_SCOPE_LINKLOCAL)
	{
		*(__be32 *)(buf + 8) = htonl(global_ptr_ll);
		global_ptr_ll++;
	}
	*(__be16 *)(buf + 12) = htons(state->PSNTP);
	*(__be16 *)(buf + 14) = htons(state->PSNLR);

	state->PSNTP++;
	

	if (state->received_once) {
		diff1 = state->last_received.tv_nsec - state->last_sent.tv_nsec;
		pr_info ("Delta receive time = %ld", diff1);

		pdm_time_delta_scale (diff1, &DTLS, &scaleDTLS);

		ktime_get_ts64 (&(state->last_sent));
		diff2 = state->last_sent.tv_nsec - state->last_received.tv_nsec;
		pr_info ("Delta send time = %ld", diff2);
		
		pdm_time_delta_scale (diff2, &DTLR, &scaleDTLR);

		buf[6] = scaleDTLR;
		buf[7] = scaleDTLS;

		*(__be16 *)(buf + 16) = htons(DTLR);
		*(__be16 *)(buf + 18) = htons(DTLS);
	}
}


void pdm_destopts_insert(struct sk_buff *skb, struct net *net, struct flowi6 *fl6)
{
	struct ipv6hdr *hdr;
	struct ipv6_opt_hdr *dst;
	unsigned char *padn;

	hdr = ipv6_hdr(skb);

	dst = (struct ipv6_opt_hdr *)(hdr + 1);
	dst->nexthdr = fl6->flowi6_proto;

	if (!net->ipv6.sysctl.pdm_encrypt)
	{
		struct ipv6_destopt_pdm *pdm;
		unsigned char buf[PDMV2_UNENC_HDR_LEN] = {0};

		dst->hdrlen = 2;

		// Generate the buf
		pdm_genopt(skb, buf, net, fl6);

		pdm = (struct ipv6_destopt_pdm *)(dst + 1);
		memcpy(pdm, buf, PDMV2_UNENC_HDR_LEN);

		padn = (unsigned char *)(pdm + 1);
		padn[0] = 1;
	}
	else
	{
		unsigned char *pdm;
		unsigned char buf[PDMV2_ENC_HDR_LEN] = {0};

		dst->hdrlen = 4;

		// Generate the buf
		pdm_genopt(skb, buf, net, fl6);

		pdm = (unsigned char *)(dst + 1);
		memcpy(pdm, buf, PDMV2_ENC_HDR_LEN);

		padn = (unsigned char *)(pdm + PDMV2_ENC_HDR_LEN);
		padn[0] = 1;
	}
}

int __init pdm_init(void)
{
	int err;

	pr_info("PDM IPv6\n");

	hash_init(data_hash);

	err = inet6_register_pdm_insert(pdm_destopts_insert);
	
	pr_info("PDM reg = %d\n", err);

	if (err)
			goto pdm_insert_reg_err;

	return 0;

pdm_insert_reg_err:
	pr_err("Failed to register PDM protocol\n");
	return err;
}

void pdm_cleanup(void)
{
	inet6_unregister_pdm_insert(pdm_destopts_insert);
}

#ifdef CONFIG_SYSCTL
static struct ctl_table ipv6_pdm_table_template[] = {
	{
		.procname	= "enable",
		.data		= &init_net.ipv6.sysctl.pdm_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "version",
		.data		= &init_net.ipv6.sysctl.pdm_version,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "encrypt",
		.data		= &init_net.ipv6.sysctl.pdm_encrypt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ },
};

struct ctl_table * __net_init ipv6_pdm_sysctl_init(struct net *net)
{
	struct ctl_table *table;

	table = kmemdup(ipv6_pdm_table_template,
			sizeof(ipv6_pdm_table_template),
			GFP_KERNEL);

	if (table) {
		table[0].data = &net->ipv6.sysctl.pdm_enabled;
		table[1].data = &net->ipv6.sysctl.pdm_version;
		table[2].data = &net->ipv6.sysctl.pdm_encrypt;
	}
	return table;
}
#endif
