#include <linux/netdevice.h>

#ifndef _LINUX_PDM_H
#define _LINUX_PDM_H

#if IS_ENABLED(CONFIG_IPV6)

typedef void ip6_pdm_insert_t(struct sk_buff *skb, struct net *net, struct flowi6 *fl6);

void pdm_insert(struct sk_buff *skb, struct net *net, struct flowi6 *fl6);

static inline void pdm6_insert(struct sk_buff *skb, struct net *net, struct flowi6 *fl6)
{
	pdm_insert(skb, net, fl6);
}

extern int inet6_register_pdm_insert(ip6_pdm_insert_t *fn);
extern int inet6_unregister_pdm_insert(ip6_pdm_insert_t *fn);

extern int				pdm_init(void);

extern void				pdm_cleanup(void);

#endif /* IS_ENABLED(CONFIG_IPV6) */

#endif /* _LINUX_PDM_H */
