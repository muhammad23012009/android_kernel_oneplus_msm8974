#ifndef __SOCK_DIAG_H__
#define __SOCK_DIAG_H__

#include <uapi/linux/sock_diag.h>

struct sk_buff;
struct nlmsghdr;
struct sock;

struct sock_diag_handler {
	__u8 family;
	int (*dump)(struct sk_buff *skb, struct nlmsghdr *nlh);
	int (*destroy)(struct sk_buff *skb, struct nlmsghdr *nlh);
};

int sock_diag_register(struct sock_diag_handler *h);
void sock_diag_unregister(struct sock_diag_handler *h);

void sock_diag_register_inet_compat(int (*fn)(struct sk_buff *skb, struct nlmsghdr *nlh));
void sock_diag_unregister_inet_compat(int (*fn)(struct sk_buff *skb, struct nlmsghdr *nlh));

int sock_diag_check_cookie(void *sk, __u32 *cookie);
void sock_diag_save_cookie(void *sk, __u32 *cookie);

int sock_diag_put_meminfo(struct sock *sk, struct sk_buff *skb, int attr);

extern struct sock *sock_diag_nlsk;

#endif
