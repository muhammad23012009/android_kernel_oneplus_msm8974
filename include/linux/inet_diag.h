#ifndef _INET_DIAG_H_
#define _INET_DIAG_H_ 1

#include <uapi/linux/inet_diag.h>

struct sock;
struct inet_hashinfo;
struct nlattr;
struct nlmsghdr;
struct sk_buff;
struct netlink_callback;

struct inet_diag_handler {
	void			(*dump)(struct sk_buff *skb,
					struct netlink_callback *cb,
					struct inet_diag_req_v2 *r,
					struct nlattr *bc);

	int			(*dump_one)(struct sk_buff *in_skb,
					const struct nlmsghdr *nlh,
					struct inet_diag_req_v2 *req);

	void			(*idiag_get_info)(struct sock *sk,
						  struct inet_diag_msg *r,
						  void *info);

	int			(*destroy)(struct sk_buff *in_skb,
					   struct inet_diag_req_v2 *req);

	__u16                   idiag_type;
};

struct inet_connection_sock;
int inet_sk_diag_fill(struct sock *sk, struct inet_connection_sock *icsk,
			      struct sk_buff *skb, struct inet_diag_req_v2 *req,
			      u32 pid, u32 seq, u16 nlmsg_flags,
			      const struct nlmsghdr *unlh);
void inet_diag_dump_icsk(struct inet_hashinfo *h, struct sk_buff *skb,
		struct netlink_callback *cb, struct inet_diag_req_v2 *r,
		struct nlattr *bc);
int inet_diag_dump_one_icsk(struct inet_hashinfo *hashinfo,
		struct sk_buff *in_skb, const struct nlmsghdr *nlh,
		struct inet_diag_req_v2 *req);

struct sock *inet_diag_find_one_icsk(struct net *net,
				     struct inet_hashinfo *hashinfo,
				     struct inet_diag_req_v2 *req);

int inet_diag_bc_sk(const struct nlattr *_bc, struct sock *sk);

extern int  inet_diag_register(const struct inet_diag_handler *handler);
extern void inet_diag_unregister(const struct inet_diag_handler *handler);
#endif /* _INET_DIAG_H_ */
