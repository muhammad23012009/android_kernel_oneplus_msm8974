/* audit.h -- Auditing support
 *
 * Copyright 2003-2004 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Written by Rickard E. (Rik) Faith <faith@redhat.com>
 *
 */
#ifndef _LINUX_AUDIT_H_
#define _LINUX_AUDIT_H_

#include <linux/sched.h>
#include <uapi/linux/audit.h>

struct audit_sig_info {
	uid_t		uid;
	pid_t		pid;
	char		ctx[0];
};

struct audit_buffer;
struct audit_context;
struct inode;
struct netlink_skb_parms;
struct path;
struct linux_binprm;
struct mq_attr;
struct mqstat;
struct audit_watch;
struct audit_tree;

struct audit_krule {
	int			vers_ops;
	u32			flags;
	u32			listnr;
	u32			action;
	u32			mask[AUDIT_BITMASK_SIZE];
	u32			buflen; /* for data alloc on list rules */
	u32			field_count;
	char			*filterkey; /* ties events to rules */
	struct audit_field	*fields;
	struct audit_field	*arch_f; /* quick access to arch field */
	struct audit_field	*inode_f; /* quick access to an inode field */
	struct audit_watch	*watch;	/* associated watch */
	struct audit_tree	*tree;	/* associated watched tree */
	struct list_head	rlist;	/* entry in audit_{watch,tree}.rules list */
	struct list_head	list;	/* for AUDIT_LIST* purposes only */
	u64			prio;
};

struct audit_field {
	u32				type;
	u32				val;
	u32				op;
	char				*lsm_str;
	void				*lsm_rule;
};

extern int __init audit_register_class(int class, unsigned *list);
extern int audit_classify_syscall(int abi, unsigned syscall);
extern int audit_classify_arch(int arch);

struct filename;

#ifdef CONFIG_AUDITSYSCALL
/* These are defined in auditsc.c */
				/* Public API */
extern int  audit_alloc(struct task_struct *task);
extern void __audit_free(struct task_struct *task);
extern void __audit_syscall_entry(int arch,
				  int major, unsigned long a0, unsigned long a1,
				  unsigned long a2, unsigned long a3);
extern void __audit_syscall_exit(int ret_success, long ret_value);
extern void __audit_getname(struct filename *name);
extern void audit_putname(struct filename *name);
extern void __audit_inode(const char *name, const struct dentry *dentry);
extern void __audit_inode_child(const struct dentry *dentry,
				const struct inode *parent);
extern void __audit_seccomp(unsigned long syscall, long signr, int code);
extern void __audit_ptrace(struct task_struct *t);

static inline int audit_dummy_context(void)
{
	void *p = current->audit_context;
	return !p || *(int *)p;
}
static inline void audit_free(struct task_struct *task)
{
	if (unlikely(task->audit_context))
		__audit_free(task);
}
static inline void audit_syscall_entry(int arch, int major, unsigned long a0,
				       unsigned long a1, unsigned long a2,
				       unsigned long a3)
{
	if (unlikely(current->audit_context))
		__audit_syscall_entry(arch, major, a0, a1, a2, a3);
}
static inline void audit_syscall_exit(void *pt_regs)
{
	if (unlikely(current->audit_context)) {
		int success = is_syscall_success(pt_regs);
		long return_code = regs_return_value(pt_regs);

		__audit_syscall_exit(success, return_code);
	}
}
static inline void audit_getname(struct filename *name)
{
	if (unlikely(!audit_dummy_context()))
		__audit_getname(name);
}
static inline void audit_inode(const char *name, const struct dentry *dentry) {
	if (unlikely(!audit_dummy_context()))
		__audit_inode(name, dentry);
}
static inline void audit_inode_child(const struct dentry *dentry,
				     const struct inode *parent) {
	if (unlikely(!audit_dummy_context()))
		__audit_inode_child(dentry, parent);
}
void audit_core_dumps(long signr);

static inline void audit_seccomp(unsigned long syscall, long signr, int code)
{
	if (unlikely(!audit_dummy_context()))
		__audit_seccomp(syscall, signr, code);
}

static inline void audit_ptrace(struct task_struct *t)
{
	if (unlikely(!audit_dummy_context()))
		__audit_ptrace(t);
}

				/* Private API (for audit.c only) */
extern unsigned int audit_serial(void);
extern int auditsc_get_stamp(struct audit_context *ctx,
			      struct timespec *t, unsigned int *serial);
extern int  audit_set_loginuid(uid_t loginuid);
#define audit_get_loginuid(t) ((t)->loginuid)
#define audit_get_sessionid(t) ((t)->sessionid)
extern void audit_log_task_context(struct audit_buffer *ab);
extern void __audit_ipc_obj(struct kern_ipc_perm *ipcp);
extern void __audit_ipc_set_perm(unsigned long qbytes, uid_t uid, gid_t gid, umode_t mode);
extern int __audit_bprm(struct linux_binprm *bprm);
extern void __audit_socketcall(int nargs, unsigned long *args);
extern int __audit_sockaddr(int len, void *addr);
extern void __audit_fd_pair(int fd1, int fd2);
extern void __audit_mq_open(int oflag, umode_t mode, struct mq_attr *attr);
extern void __audit_mq_sendrecv(mqd_t mqdes, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout);
extern void __audit_mq_notify(mqd_t mqdes, const struct sigevent *notification);
extern void __audit_mq_getsetattr(mqd_t mqdes, struct mq_attr *mqstat);
extern int __audit_log_bprm_fcaps(struct linux_binprm *bprm,
				  const struct cred *new,
				  const struct cred *old);
extern void __audit_log_capset(pid_t pid, const struct cred *new, const struct cred *old);
extern void __audit_mmap_fd(int fd, int flags);

static inline void audit_ipc_obj(struct kern_ipc_perm *ipcp)
{
	if (unlikely(!audit_dummy_context()))
		__audit_ipc_obj(ipcp);
}
static inline void audit_fd_pair(int fd1, int fd2)
{
	if (unlikely(!audit_dummy_context()))
		__audit_fd_pair(fd1, fd2);
}
static inline void audit_ipc_set_perm(unsigned long qbytes, uid_t uid, gid_t gid, umode_t mode)
{
	if (unlikely(!audit_dummy_context()))
		__audit_ipc_set_perm(qbytes, uid, gid, mode);
}
static inline int audit_bprm(struct linux_binprm *bprm)
{
	if (unlikely(!audit_dummy_context()))
		return __audit_bprm(bprm);
	return 0;
}
static inline void audit_socketcall(int nargs, unsigned long *args)
{
	if (unlikely(!audit_dummy_context()))
		__audit_socketcall(nargs, args);
}
static inline int audit_sockaddr(int len, void *addr)
{
	if (unlikely(!audit_dummy_context()))
		return __audit_sockaddr(len, addr);
	return 0;
}
static inline void audit_mq_open(int oflag, umode_t mode, struct mq_attr *attr)
{
	if (unlikely(!audit_dummy_context()))
		__audit_mq_open(oflag, mode, attr);
}
static inline void audit_mq_sendrecv(mqd_t mqdes, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout)
{
	if (unlikely(!audit_dummy_context()))
		__audit_mq_sendrecv(mqdes, msg_len, msg_prio, abs_timeout);
}
static inline void audit_mq_notify(mqd_t mqdes, const struct sigevent *notification)
{
	if (unlikely(!audit_dummy_context()))
		__audit_mq_notify(mqdes, notification);
}
static inline void audit_mq_getsetattr(mqd_t mqdes, struct mq_attr *mqstat)
{
	if (unlikely(!audit_dummy_context()))
		__audit_mq_getsetattr(mqdes, mqstat);
}

static inline int audit_log_bprm_fcaps(struct linux_binprm *bprm,
				       const struct cred *new,
				       const struct cred *old)
{
	if (unlikely(!audit_dummy_context()))
		return __audit_log_bprm_fcaps(bprm, new, old);
	return 0;
}

static inline void audit_log_capset(pid_t pid, const struct cred *new,
				   const struct cred *old)
{
	if (unlikely(!audit_dummy_context()))
		__audit_log_capset(pid, new, old);
}

static inline void audit_mmap_fd(int fd, int flags)
{
	if (unlikely(!audit_dummy_context()))
		__audit_mmap_fd(fd, flags);
}

extern int audit_n_rules;
extern int audit_signals;
#else /* CONFIG_AUDITSYSCALL */
#define audit_alloc(t) ({ 0; })
#define audit_free(t) do { ; } while (0)
#define audit_syscall_entry(ta,a,b,c,d,e) do { ; } while (0)
#define audit_syscall_exit(r) do { ; } while (0)
#define audit_dummy_context() 1
#define audit_getname(n) do { ; } while (0)
#define audit_putname(n) do { ; } while (0)
#define __audit_inode(n,d) do { ; } while (0)
#define __audit_inode_child(i,p) do { ; } while (0)
#define audit_inode(n,d) do { (void)(d); } while (0)
#define audit_inode_child(i,p) do { ; } while (0)
#define audit_core_dumps(i) do { ; } while (0)
#define audit_seccomp(i,s,c) do { ; } while (0)
#define auditsc_get_stamp(c,t,s) (0)
#define audit_get_loginuid(t) (-1)
#define audit_get_sessionid(t) (-1)
#define audit_log_task_context(b) do { ; } while (0)
#define audit_ipc_obj(i) ((void)0)
#define audit_ipc_set_perm(q,u,g,m) ((void)0)
#define audit_bprm(p) ({ 0; })
#define audit_socketcall(n,a) ((void)0)
#define audit_fd_pair(n,a) ((void)0)
#define audit_sockaddr(len, addr) ({ 0; })
#define audit_mq_open(o,m,a) ((void)0)
#define audit_mq_sendrecv(d,l,p,t) ((void)0)
#define audit_mq_notify(d,n) ((void)0)
#define audit_mq_getsetattr(d,s) ((void)0)
#define audit_log_bprm_fcaps(b, ncr, ocr) ({ 0; })
#define audit_log_capset(pid, ncr, ocr) ((void)0)
#define audit_mmap_fd(fd, flags) ((void)0)
#define audit_ptrace(t) ((void)0)
#define audit_n_rules 0
#define audit_signals 0
#endif /* CONFIG_AUDITSYSCALL */

#ifdef CONFIG_AUDIT
/* These are defined in audit.c */
				/* Public API */
extern __printf(4, 5)
void audit_log(struct audit_context *ctx, gfp_t gfp_mask, int type,
	       const char *fmt, ...);

extern struct audit_buffer *audit_log_start(struct audit_context *ctx, gfp_t gfp_mask, int type);
extern __printf(2, 3)
void audit_log_format(struct audit_buffer *ab, const char *fmt, ...);
extern void		    audit_log_end(struct audit_buffer *ab);
extern int		    audit_string_contains_control(const char *string,
							  size_t len);
extern void		    audit_log_n_hex(struct audit_buffer *ab,
					  const unsigned char *buf,
					  size_t len);
extern void		    audit_log_n_string(struct audit_buffer *ab,
					       const char *buf,
					       size_t n);
#define audit_log_string(a,b) audit_log_n_string(a, b, strlen(b));
extern void		    audit_log_n_untrustedstring(struct audit_buffer *ab,
							const char *string,
							size_t n);
extern void		    audit_log_untrustedstring(struct audit_buffer *ab,
						      const char *string);
extern void		    audit_log_d_path(struct audit_buffer *ab,
					     const char *prefix,
					     const struct path *path);
extern void		    audit_log_key(struct audit_buffer *ab,
					  char *key);
extern void		    audit_log_link_denied(const char *operation,
						  struct path *link);
extern void		    audit_log_lost(const char *message);
#ifdef CONFIG_SECURITY
extern void 		    audit_log_secctx(struct audit_buffer *ab, u32 secid);
#else
#define audit_log_secctx(b,s) do { ; } while (0)
#endif

extern int		    audit_update_lsm_rules(void);

				/* Private API (for audit.c only) */
extern int audit_filter_user(struct netlink_skb_parms *cb);
extern int audit_filter_type(int type);
extern int  audit_receive_filter(int type, int pid, int uid, int seq,
				void *data, size_t datasz, uid_t loginuid,
				u32 sessionid, u32 sid);
extern int audit_enabled;
#else
#define audit_log(c,g,t,f,...) do { ; } while (0)
#define audit_log_start(c,g,t) ({ NULL; })
#define audit_log_vformat(b,f,a) do { ; } while (0)
#define audit_log_format(b,f,...) do { ; } while (0)
#define audit_log_end(b) do { ; } while (0)
#define audit_log_n_hex(a,b,l) do { ; } while (0)
#define audit_log_n_string(a,c,l) do { ; } while (0)
#define audit_log_string(a,c) do { ; } while (0)
#define audit_log_n_untrustedstring(a,n,s) do { ; } while (0)
#define audit_log_untrustedstring(a,s) do { ; } while (0)
#define audit_log_d_path(b, p, d) do { ; } while (0)
#define audit_log_key(b, k) do { ; } while (0)
#define audit_log_link_denied(o, l) do { ; } while (0)
#define audit_log_secctx(b,s) do { ; } while (0)
#define audit_enabled 0
#endif
#endif
