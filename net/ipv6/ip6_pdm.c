#include <linux/export.h>
#include <linux/pdm.h>
#include <net/ipv6.h>

#if IS_ENABLED(CONFIG_IPV6)

static ip6_pdm_insert_t __rcu *ip6_pdm_insert;

int inet6_register_pdm_insert(ip6_pdm_insert_t *fn)
{
	return (cmpxchg((ip6_pdm_insert_t **)&ip6_pdm_insert, NULL, fn) == NULL) ?
		0 : -EBUSY;
}
EXPORT_SYMBOL(inet6_register_pdm_insert);

int inet6_unregister_pdm_insert(ip6_pdm_insert_t *fn)
{
	int ret;

	ret = (cmpxchg((ip6_pdm_insert_t **)&ip6_pdm_insert, fn, NULL) == fn) ?
	      0 : -EINVAL;

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(inet6_unregister_pdm_insert);

void pdm_insert(struct sk_buff *skb, struct net *net, struct flowi6 *fl6)
{
	ip6_pdm_insert_t *insert;

	rcu_read_lock();
	insert = rcu_dereference(ip6_pdm_insert);
	if (insert)
		insert(skb, net, fl6);
	rcu_read_unlock();
}
EXPORT_SYMBOL(pdm_insert);

#endif
