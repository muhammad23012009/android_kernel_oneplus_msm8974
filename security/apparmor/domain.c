/*
 * AppArmor security module
 *
 * This file contains AppArmor policy attachment and domain transitions
 *
 * Copyright (C) 2002-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/syscalls.h>
#include <linux/tracehook.h>
#include <linux/personality.h>

#include "include/audit.h"
#include "include/apparmorfs.h"
#include "include/context.h"
#include "include/domain.h"
#include "include/file.h"
#include "include/ipc.h"
#include "include/match.h"
#include "include/path.h"
#include "include/policy.h"

/**
 * aa_free_domain_entries - free entries in a domain table
 * @domain: the domain table to free  (MAYBE NULL)
 */
void aa_free_domain_entries(struct aa_domain *domain)
{
	int i;
	if (domain) {
		if (!domain->table)
			return;

		for (i = 0; i < domain->size; i++)
			kzfree(domain->table[i]);
		kzfree(domain->table);
		domain->table = NULL;
	}
}

/**
 * may_change_ptraced_domain - check if can change profile on ptraced task
 * @to_profile: profile to change to  (NOT NULL)
 * @info: message if there is an error
 *
 * Check if current is ptraced and if so if the tracing task is allowed
 * to trace the new domain
 *
 * Returns: %0 or error if change not allowed
 */
static int may_change_ptraced_domain(struct aa_profile *to_profile,
				     const char **info)
{
	struct task_struct *tracer;
	struct aa_label *tracerl = NULL;
	int error = 0;

	rcu_read_lock();
	tracer = ptrace_parent(current);
	if (tracer)
		/* released below */
		tracerl = aa_get_task_label(tracer);

	/* not ptraced */
	if (!tracer || unconfined(tracerl))
		goto out;

	error = aa_may_ptrace(tracerl, &to_profile->label, PTRACE_MODE_ATTACH);

out:
	rcu_read_unlock();
	aa_put_label(tracerl);

	if (error)
		*info = "ptrace prevents transition";
	return error;
}

/**
 * change_profile_perms - find permissions for change_profile
 * @profile: the current profile  (NOT NULL)
 * @ns: the namespace being switched to  (NOT NULL)
 * @name: the name of the profile to change to  (NOT NULL)
 * @request: requested perms
 * @start: state to start matching in
 *
 * Returns: permission set
 */
static struct file_perms change_profile_perms(struct aa_profile *profile,
					      struct aa_namespace *ns,
					      const char *name, u32 request,
					      unsigned int start)
{
	struct file_perms perms;
	struct path_cond cond = { };
	unsigned int state;

	if (profile_unconfined(profile)) {
		perms.allow = AA_MAY_CHANGE_PROFILE | AA_MAY_ONEXEC;
		perms.audit = perms.quiet = perms.kill = 0;
		return perms;
	} else if (!profile->file.dfa) {
		return nullperms;
	} else if ((ns == profile->ns)) {
		/* try matching against rules with out namespace prepended */
		aa_str_perms(profile->file.dfa, start, name, &cond, &perms);
		if (COMBINED_PERM_MASK(perms) & request)
			return perms;
	}

	/* try matching with namespace name and then profile */
	state = aa_dfa_match(profile->file.dfa, start, ns->base.name);
	state = aa_dfa_match_len(profile->file.dfa, state, ":", 1);
	aa_str_perms(profile->file.dfa, state, name, &cond, &perms);

	return perms;
}

/**
 * __attach_match_ - find an attachment match
 * @name - to match against  (NOT NULL)
 * @head - profile list to walk  (NOT NULL)
 *
 * Do a linear search on the profiles in the list.  There is a matching
 * preference where an exact match is preferred over a name which uses
 * expressions to match, and matching expressions with the greatest
 * xmatch_len are preferred.
 *
 * Requires: @head not be shared or have appropriate locks held
 *
 * Returns: profile or NULL if no match found
 */
static struct aa_profile *__attach_match(const char *name,
					 struct list_head *head)
{
	int len = 0;
	struct aa_profile *profile, *candidate = NULL;

	list_for_each_entry_rcu(profile, head, base.list) {
		if (profile->label.flags & FLAG_NULL)
			continue;
		if (profile->xmatch && profile->xmatch_len > len) {
			unsigned int state = aa_dfa_match(profile->xmatch,
							  DFA_START, name);
			u32 perm = dfa_user_allow(profile->xmatch, state);
			/* any accepting state means a valid match. */
			if (perm & MAY_EXEC) {
				candidate = profile;
				len = profile->xmatch_len;
			}
		} else if (!strcmp(profile->base.name, name))
			/* exact non-re match, no more searching required */
			return profile;
	}

	return candidate;
}

/**
 * find_attach - do attachment search for unconfined processes
 * @ns: the current namespace  (NOT NULL)
 * @list: list to search  (NOT NULL)
 * @name: the executable name to match against  (NOT NULL)
 *
 * Returns: profile or NULL if no match found
 */
static struct aa_profile *find_attach(struct aa_namespace *ns,
				      struct list_head *list, const char *name)
{
	struct aa_profile *profile;

	rcu_read_lock();
	profile = aa_get_profile(__attach_match(name, list));
	rcu_read_unlock();

	return profile;
}

/**
 * separate_fqname - separate the namespace and profile names
 * @fqname: the fqname name to split  (NOT NULL)
 * @ns_name: the namespace name if it exists  (NOT NULL)
 *
 * This is the xtable equivalent routine of aa_split_fqname.  It finds the
 * split in an xtable fqname which contains an embedded \0 instead of a :
 * if a namespace is specified.  This is done so the xtable is constant and
 * isn't re-split on every lookup.
 *
 * Either the profile or namespace name may be optional but if the namespace
 * is specified the profile name termination must be present.  This results
 * in the following possible encodings:
 * profile_name\0
 * :ns_name\0profile_name\0
 * :ns_name\0\0
 *
 * NOTE: the xtable fqname is pre-validated at load time in unpack_trans_table
 *
 * Returns: profile name if it is specified else NULL
 */
static const char *separate_fqname(const char *fqname, const char **ns_name)
{
	const char *name;

	if (fqname[0] == ':') {
		/* In this case there is guaranteed to be two \0 terminators
		 * in the string.  They are verified at load time by
		 * by unpack_trans_table
		 */
		*ns_name = fqname + 1;		/* skip : */
		name = *ns_name + strlen(*ns_name) + 1;
		if (!*name)
			name = NULL;
	} else {
		*ns_name = NULL;
		name = fqname;
	}

	return name;
}

static const char *next_name(int xtype, const char *name)
{
	return NULL;
}

/**
 * x_table_lookup - lookup an x transition name via transition table
 * @profile: current profile (NOT NULL)
 * @xindex: index into x transition table
 *
 * Returns: refcounted profile, or NULL on failure (MAYBE NULL)
 */
struct aa_profile *x_table_lookup(struct aa_profile *profile, u32 xindex)
{
	struct aa_profile *new_profile = NULL;
	struct aa_namespace *ns = profile->ns;
	u32 xtype = xindex & AA_X_TYPE_MASK;
	int index = xindex & AA_X_INDEX_MASK;
	const char *name;

	/* index is guaranteed to be in range, validated at load time */
	for (name = profile->file.trans.table[index]; !new_profile && name;
	     name = next_name(xtype, name)) {
		struct aa_namespace *new_ns;
		const char *xname = NULL;

		new_ns = NULL;
		if (xindex & AA_X_CHILD) {
			/* release by caller */
			new_profile = aa_find_child(profile, name);
			continue;
		} else if (*name == ':') {
			/* switching namespace */
			const char *ns_name;
			xname = name = separate_fqname(name, &ns_name);
			if (!xname)
				/* no name so use profile name */
				xname = profile->base.hname;
			if (*ns_name == '@') {
				/* TODO: variable support */
				;
			}
			/* released below */
			new_ns = aa_find_namespace(ns, ns_name);
			if (!new_ns)
				continue;
		} else if (*name == '@') {
			/* TODO: variable support */
			continue;
		} else {
			/* basic namespace lookup */
			xname = name;
		}

		/* released by caller */
		new_profile = aa_lookup_profile(new_ns ? new_ns : ns, xname);
		aa_put_namespace(new_ns);
	}

	/* released by caller */
	return new_profile;
}

/**
 * x_to_profile - get target profile for a given xindex
 * @profile: current profile  (NOT NULL)
 * @name: name to lookup (NOT NULL)
 * @xindex: index into x transition table
 *
 * find profile for a transition index
 *
 * Returns: refcounted profile or NULL if not found available
 */
static struct aa_profile *x_to_profile(struct aa_profile *profile,
				       const char *name, u32 xindex)
{
	struct aa_profile *new_profile = NULL;
	struct aa_namespace *ns = profile->ns;
	u32 xtype = xindex & AA_X_TYPE_MASK;

	switch (xtype) {
	case AA_X_NONE:
		/* fail exec unless ix || ux fallback - handled by caller */
		return NULL;
	case AA_X_NAME:
		if (xindex & AA_X_CHILD)
			/* released by caller */
			new_profile = find_attach(ns, &profile->base.profiles,
						  name);
		else
			/* released by caller */
			new_profile = find_attach(ns, &ns->base.profiles,
						  name);
		break;
	case AA_X_TABLE:
		/* released by caller */
		new_profile = x_table_lookup(profile, xindex);
		break;
	}

	/* released by caller */
	return new_profile;
}

/**
 * apparmor_bprm_set_creds - set the new creds on the bprm struct
 * @bprm: binprm for the exec  (NOT NULL)
 *
 * Returns: %0 or error on failure
 */
int apparmor_bprm_set_creds(struct linux_binprm *bprm)
{
	struct aa_task_cxt *cxt;
	struct aa_label *label;
	struct aa_profile *profile, *new_profile = NULL;
	struct aa_namespace *ns;
	char *buffer = NULL;
	unsigned int state;
	struct file_perms perms = {};
	struct path_cond cond = {
		file_inode(bprm->file)->i_uid,
		file_inode(bprm->file)->i_mode
	};
	const char *name = NULL, *target = NULL, *info = NULL;
	int error = cap_bprm_set_creds(bprm);
	if (error)
		return error;

	if (bprm->cred_prepared)
		return 0;

	cxt = cred_cxt(bprm->cred);
	BUG_ON(!cxt);

	label = aa_get_newest_label(cxt->label);
	profile = labels_profile(label);
	/*
	 * get the namespace from the replacement profile as replacement
	 * can change the namespace
	 */
	ns = profile->ns;
	state = profile->file.start;

	/* buffer freed below, name is pointer into buffer */
	get_buffers(buffer);
	error = aa_path_name(&bprm->file->f_path, profile->path_flags, buffer,
			     &name, &info, profile->disconnected);
	if (error) {
		if (profile_unconfined(profile) ||
		    (profile->label.flags & FLAG_IX_ON_NAME_ERROR))
			error = 0;
		name = bprm->filename;
		goto audit;
	}

	/* Test for onexec first as onexec directives override other
	 * x transitions.
	 */
	if (profile_unconfined(profile)) {
		/* unconfined task */
		if (cxt->onexec)
			/* change_profile on exec already been granted */
			new_profile = labels_profile(aa_get_label(cxt->onexec));
		else
			new_profile = find_attach(ns, &ns->base.profiles, name);
		if (!new_profile)
			goto cleanup;
		/*
		 * NOTE: Domain transitions from unconfined are allowed
		 * even when no_new_privs is set because this aways results
		 * in a further reduction of permissions.
		 */
		goto apply;
	}

	/* find exec permissions for name */
	state = aa_str_perms(profile->file.dfa, state, name, &cond, &perms);
	if (cxt->onexec) {
		struct file_perms cp;
		info = "change_profile onexec";
		if (!(perms.allow & AA_MAY_ONEXEC))
			goto audit;

		/* test if this exec can be paired with change_profile onexec.
		 * onexec permission is linked to exec with a standard pairing
		 * exec\0change_profile
		 */
		state = aa_dfa_null_transition(profile->file.dfa, state);
		cp = change_profile_perms(profile, labels_profile(cxt->onexec)->ns,
					  labels_profile(cxt->onexec)->base.name,
					  AA_MAY_ONEXEC, state);

		if (!(cp.allow & AA_MAY_ONEXEC))
			goto audit;
		new_profile = labels_profile(aa_get_newest_label(cxt->onexec));
		goto apply;
	}

	if (perms.allow & MAY_EXEC) {
		/* exec permission determine how to transition */
		new_profile = x_to_profile(profile, name, perms.xindex);
		if (!new_profile) {
			if (perms.xindex & AA_X_INHERIT) {
				/* (p|c|n)ix - don't change profile but do
				 * use the newest version, which was picked
				 * up above when getting profile
				 */
				info = "ix fallback";
				new_profile = aa_get_profile(profile);
				goto x_clear;
			} else if (perms.xindex & AA_X_UNCONFINED) {
				new_profile = labels_profile(aa_get_newest_label(&ns->unconfined->label));
				info = "ux fallback";
			} else {
				error = -EACCES;
				info = "profile not found";
				/* remove MAY_EXEC to audit as failure */
				perms.allow &= ~MAY_EXEC;
			}
		}
	} else if (COMPLAIN_MODE(profile)) {
		/* no exec permission - learning mode. break rcu lock */
		put_buffers(buffer);
		name = NULL;
		new_profile = aa_new_null_profile(profile, 0);
		if (!new_profile) {
			error = -ENOMEM;
			info = "could not create null profile";
		} else {
			error = -EACCES;
			target = new_profile->base.hname;
		}
		perms.xindex |= AA_X_UNSAFE;
		/* re-aquire buffer and rcu readlock and re-get name */
		get_buffers(buffer);
		if (!error)
			error = aa_path_name(&bprm->file->f_path,
					     profile->path_flags, buffer,
					     &name, &info, profile->disconnected);
	} else
		/* fail exec */
		error = -EACCES;

	/*
	 * Policy has specified a domain transition, if no_new_privs then
	 * fail the exec.
	 */
	if (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS) {
		aa_put_profile(new_profile);
		error = -EPERM;
		goto cleanup;
	}

	if (!new_profile)
		goto audit;

	if (bprm->unsafe & LSM_UNSAFE_SHARE) {
		/* FIXME: currently don't mediate shared state */
		;
	}

	if (bprm->unsafe & (LSM_UNSAFE_PTRACE | LSM_UNSAFE_PTRACE_CAP)) {
		error = may_change_ptraced_domain(new_profile, &info);
		if (error) {
			aa_put_profile(new_profile);
			goto audit;
		}
	}

	/* Determine if secure exec is needed.
	 * Can be at this point for the following reasons:
	 * 1. unconfined switching to confined
	 * 2. confined switching to different confinement
	 * 3. confined switching to unconfined
	 *
	 * Cases 2 and 3 are marked as requiring secure exec
	 * (unless policy specified "unsafe exec")
	 *
	 * bprm->unsafe is used to cache the AA_X_UNSAFE permission
	 * to avoid having to recompute in secureexec
	 */
	if (!(perms.xindex & AA_X_UNSAFE)) {
		AA_DEBUG("scrubbing environment variables for %s profile=%s\n",
			 name, new_profile->base.hname);
		bprm->unsafe |= AA_SECURE_X_NEEDED;
	}
apply:
	target = new_profile->base.hname;
	/* when transitioning profiles clear unsafe personality bits */
	bprm->per_clear |= PER_CLEAR_ON_SETID;

x_clear:
	aa_put_label(cxt->label);
	/* transfer new profile reference will be released when cxt is freed */
	cxt->label = &new_profile->label;

	/* clear out all temporary/transitional state from the context */
	aa_clear_task_cxt_trans(cxt);

audit:
	error = aa_audit_file(profile, &perms, OP_EXEC, MAY_EXEC, name, target,
			      cond.uid, info, error);

cleanup:
	aa_put_label(label);
	put_buffers(buffer);

	return error;
}

/**
 * apparmor_bprm_secureexec - determine if secureexec is needed
 * @bprm: binprm for exec  (NOT NULL)
 *
 * Returns: %1 if secureexec is needed else %0
 */
int apparmor_bprm_secureexec(struct linux_binprm *bprm)
{
	int ret = cap_bprm_secureexec(bprm);

	/* the decision to use secure exec is computed in set_creds
	 * and stored in bprm->unsafe.
	 */
	if (!ret && (bprm->unsafe & AA_SECURE_X_NEEDED))
		ret = 1;

	return ret;
}

/*
 * Functions for self directed profile change
 */

/**
 * new_compound_name - create an hname with @n2 appended to @n1
 * @n1: base of hname  (NOT NULL)
 * @n2: name to append (NOT NULL)
 *
 * Returns: new name or NULL on error
 */
static char *new_compound_name(const char *n1, const char *n2)
{
	char *name = kmalloc(strlen(n1) + strlen(n2) + 3, GFP_KERNEL);
	if (name)
		sprintf(name, "%s//%s", n1, n2);
	return name;
}

/**
 * aa_change_hat - change hat to/from subprofile
 * @hats: vector of hat names to try changing into (MAYBE NULL if @count == 0)
 * @count: number of hat names in @hats
 * @token: magic value to validate the hat change
 * @permtest: true if this is just a permission test
 *
 * Change to the first profile specified in @hats that exists, and store
 * the @hat_magic in the current task context.  If the count == 0 and the
 * @token matches that stored in the current task context, return to the
 * top level profile.
 *
 * Returns %0 on success, error otherwise.
 */
int aa_change_hat(const char *hats[], int count, u64 token, bool permtest)
{
	const struct cred *cred;
	struct aa_task_cxt *cxt;
	struct aa_label *label, *previous;
	struct aa_profile *profile, *hat = NULL;
	char *name = NULL;
	int i;
	struct file_perms perms = {};
	const char *target = NULL, *info = NULL;
	int error = 0;

	/*
	 * Fail explicitly requested domain transitions if no_new_privs.
	 * There is no exception for unconfined as change_hat is not
	 * available.
	 */
	if (task_no_new_privs(current))
		return -EPERM;

	/* released below */
	cred = get_current_cred();
	cxt = cred_cxt(cred);
	label = aa_get_newest_cred_label(cred);
	previous = cxt->previous;

	profile = labels_profile(label);

	if (unconfined(label)) {
		info = "unconfined";
		error = -EPERM;
		goto audit;
	}

	if (count) {
		/* attempting to change into a new hat or switch to a sibling */
		struct aa_profile *root;
		if (PROFILE_IS_HAT(profile))
			root = aa_get_profile_rcu(&profile->parent);
		else
			root = aa_get_profile(labels_profile(label));

		/* find first matching hat */
		for (i = 0; i < count && !hat; i++)
			/* released below */
			hat = aa_find_child(root, hats[i]);
		if (!hat) {
			if (!COMPLAIN_MODE(root) || permtest) {
				if (list_empty(&root->base.profiles))
					error = -ECHILD;
				else
					error = -ENOENT;
				aa_put_profile(root);
				goto out;
			}

			/*
			 * In complain mode and failed to match any hats.
			 * Audit the failure is based off of the first hat
			 * supplied.  This is done due how userspace
			 * interacts with change_hat.
			 *
			 * TODO: Add logging of all failed hats
			 */

			/* freed below */
			name = new_compound_name(root->base.hname, hats[0]);
			aa_put_profile(root);
			target = name;
			/* released below */
			hat = aa_new_null_profile(profile, 1);
			if (!hat) {
				info = "failed null profile create";
				error = -ENOMEM;
				goto audit;
			}
		} else {
			aa_put_profile(root);
			target = hat->base.hname;
			if (!PROFILE_IS_HAT(hat)) {
				info = "target not hat";
				error = -EPERM;
				goto audit;
			}
		}

		error = may_change_ptraced_domain(hat, &info);
		if (error) {
			error = -EPERM;
			goto audit;
		}

		if (!permtest) {
			error = aa_set_current_hat(&hat->label, token);
			if (error == -EACCES)
				/* kill task in case of brute force attacks */
				perms.kill = AA_MAY_CHANGEHAT;
			else if (name && !error)
				/* reset error for learning of new hats */
				error = -ENOENT;
		}
	} else if (previous) {
		/* Return to saved label.  Kill task if restore fails
		 * to avoid brute force attacks
		 */
		target = previous->hname;
		error = aa_restore_previous_label(token);
		perms.kill = AA_MAY_CHANGEHAT;
	} else
		/* ignore restores when there is no saved profile */
		goto out;

audit:
	if (!permtest)
		error = aa_audit_file(profile, &perms, OP_CHANGE_HAT,
				      AA_MAY_CHANGEHAT, NULL, target,
				      GLOBAL_ROOT_UID, info, error);

out:
	aa_put_profile(hat);
	aa_put_label(label);
	kfree(name);
	put_cred(cred);

	return error;
}

/**
 * aa_change_profile - perform a one-way profile transition
 * @ns_name: name of the profile namespace to change to (MAYBE NULL)
 * @hname: name of profile to change to (MAYBE NULL)
 * @onexec: whether this transition is to take place immediately or at exec
 * @permtest: true if this is just a permission test
 *
 * Change to new profile @name.  Unlike with hats, there is no way
 * to change back.  If @name isn't specified the current profile name is
 * used.
 * If @onexec then the transition is delayed until
 * the next exec.
 *
 * Returns %0 on success, error otherwise.
 */
int aa_change_profile(const char *ns_name, const char *hname, bool onexec,
		      bool permtest)
{
	const struct cred *cred;
	struct aa_label *label;
	struct aa_profile *profile, *target = NULL;
	struct aa_namespace *ns = NULL;
	struct file_perms perms = {};
	const char *name = NULL, *info = NULL;
	int op, error = 0;
	u32 request;

	if (!hname && !ns_name)
		return -EINVAL;

	if (onexec) {
		request = AA_MAY_ONEXEC;
		op = OP_CHANGE_ONEXEC;
	} else {
		request = AA_MAY_CHANGE_PROFILE;
		op = OP_CHANGE_PROFILE;
	}

	cred = get_current_cred();
	label = aa_get_newest_cred_label(cred);
	profile = labels_profile(label);

	/*
	 * Fail explicitly requested domain transitions if no_new_privs
	 * and not unconfined.
	 * Domain transitions from unconfined are allowed even when
	 * no_new_privs is set because this aways results in a reduction
	 * of permissions.
	 */
	if (task_no_new_privs(current) && !unconfined(label)) {
		aa_put_label(label);
		put_cred(cred);
		return -EPERM;
	}

	if (ns_name) {
		/* released below */
		ns = aa_find_namespace(profile->ns, ns_name);
		if (!ns) {
			/* we don't create new namespace in complain mode */
			name = ns_name;
			info = "namespace not found";
			error = -ENOENT;
			goto audit;
		}
	} else
		/* released below */
		ns = aa_get_namespace(profile->ns);

	/* if the name was not specified, use the name of the current profile */
	if (!hname) {
		if (profile_unconfined(profile))
			hname = ns->unconfined->base.hname;
		else
			hname = profile->base.hname;
	}

	perms = change_profile_perms(profile, ns, hname, request,
				     profile->file.start);
	if (!(perms.allow & request)) {
		error = -EACCES;
		goto audit;
	}

	/* released below */
	target = aa_lookup_profile(ns, hname);
	if (!target) {
		info = "profile not found";
		error = -ENOENT;
		if (permtest || !COMPLAIN_MODE(profile))
			goto audit;
		/* released below */
		target = aa_new_null_profile(profile, 0);
		if (!target) {
			info = "failed null profile create";
			error = -ENOMEM;
			goto audit;
		}
	}

	/* check if tracing task is allowed to trace target domain */
	error = may_change_ptraced_domain(target, &info);
	if (error)
		goto audit;

	if (permtest)
		goto audit;

	if (onexec)
		error = aa_set_current_onexec(&target->label);
	else
		error = aa_replace_current_label(&target->label);

audit:
	if (!permtest)
		error = aa_audit_file(profile, &perms, op, request, name,
				      hname, GLOBAL_ROOT_UID, info, error);

	aa_put_namespace(ns);
	aa_put_profile(target);
	aa_put_label(label);
	put_cred(cred);

	return error;
}
