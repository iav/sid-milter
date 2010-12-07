/*
**  Copyright (c) 2004, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_frame_c_id[] = "@(#)$Id: sm-marid-frame.c,v 1.5 2008/05/15 18:37:24 msk Exp $";
#endif /* !lint */

/*
**  SM_MARID_CHECK_HOST_CHAIN -- mark a check-host as derived from another.
**
**	Mark a new check-host context as derived from another.
**
**	This information is used by recursive calls to check_host to
**	avoid infinite recursion.  (It is an error to recursively
**	ask questions we're already in the process of answering.)
**
**	This happeens between a call to sm_marid_check_host_new()
**	and a call to sm_marid_check_host().
**
**	Parameters:
**		new_context -- the context that was most recently created
**		old_context -- the context that caused it to be created.
**
**	Returns:
**		none.
*/

sm_marid_frame *
sm_marid_check_host_frame(
	sm_marid 		*marid,
	char const		*ip,
	char const		*domain,
	char const		*sender,
	sm_marid_deliver_result	*deliver)
{
	sm_marid_frame 		*smf;
	size_t			ip_n, domain_n, sender_n;
	char			*heap;

	if (ip == NULL)
		ip = "";
	ip_n = strlen(ip) + 1;
	if (domain == NULL)
		domain = "";
	domain_n = strlen(domain) + 1;
	if (sender == NULL)
		sender = "";
	sender_n = strlen(sender) + 1;

	smf = sm_marid_arena_alloc(marid,
		ip_n + domain_n + sender_n + sizeof(*smf));
	if (smf == NULL)
		return NULL;
	memset(smf, 0, sizeof(*smf));

	heap = (char *)(smf + 1);
	smf->smf_query_ip = memcpy(heap, ip, ip_n);
	heap += ip_n;
	smf->smf_query_sender = memcpy(heap, sender, sender_n);
	heap += sender_n;
	smf->smf_query_domain = memcpy(heap, domain, domain_n);

	smf->smf_deliver_result = deliver;
	smf->smf_prev = marid->sm_frame;
	smf->smf_depth = marid->sm_frame == NULL
		?  0
		: marid->sm_frame->smf_depth + 1;
	marid->sm_frame = smf;

	return smf;
}


/*
**  SM_MARID_CHECK_HOST_DELIVER_RESULT -- complete processing
**
**	This is a utility that completes processing of one check_host()
**	frame by calling the delivery callback.
**
**	Parameters:
**		context -- context initialized with sm_marid_check_host_new()
**
**	Returns:
**		none
*/

void
sm_marid_check_host_deliver_result(sm_marid *context)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, context->sm_frame != NULL))
		return;

	if (sm_marid_check_host_record_modifiers(context))
		return;

	smf = context->sm_frame;

	if (  smf->smf_result == SM_MARID_FAIL
	   && smf->smf_reason == SM_MARID_NOT_PERMITTED
	   && smf->smf_redirect_s != NULL
	   && smf->smf_redirect_tried == 0)
	{
		smf->smf_redirect_tried = 1;
		sm_marid_mod_redirect_execute(context);
		return;
	}

	if (  smf->smf_result == SM_MARID_FAIL
	   && smf->smf_reason == SM_MARID_NOT_PERMITTED
	   && smf->smf_explanation == NULL
	   && smf->smf_exp_tried == 0)
	{
		smf->smf_exp_tried = 1;
		sm_marid_mod_exp_execute(context);
		return;
	}

	sm_marid_check_host_log_result(context);

	/* don't lose any redirect found */
	if (smf->smf_redirect_s != NULL && smf->smf_prev != NULL &&
	    smf->smf_prev->smf_redirect_s == NULL)
	{
		smf->smf_prev->smf_redirect_s = smf->smf_redirect_s;
		smf->smf_prev->smf_redirect_e = smf->smf_redirect_e;
	}
 
	context->sm_frame = smf->smf_prev;
 	(* smf->smf_deliver_result)(context, smf);
}

/*
**  SM_MARID_CHECK_HOST_DNS_RESULT_MARID -- handle result of an DNS query
**
**	Called in reponse to a MARID lookup.
**
**	Parameters:
**		context -- calling context
**		err -- DNS lookup error or 0
**		vec -- results
**		vec_n -- # of results
**
**	Returns:
**		none
*/

static void
sm_marid_check_host_dns_result_marid(
	sm_marid		*context,
	int			err,
	char const * const 	*vec,
	size_t			vec_n)
{
	sm_marid_frame		*smf;
	char const		*s, *e;
	char			*heap;
	char const		*record;
	size_t			i;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;

	/*
	**  If the domain does not exist (NXDOMAIN),
	**  check_host() exits immediately with the result "Fail"
	**  and a reason of "Domain Does Not Exist"
	*/

	if (err == SM_MARID_ERR_NXDOMAIN)
	{
		smf->smf_result = SM_MARID_FAIL;
		smf->smf_reason = SM_MARID_DOMAIN_DOES_NOT_EXIST;

 		sm_marid_check_host_deliver_result(context);
		return;
	}

   	/* 
	**  If the DNS lookup returns a server failure (SERVFAIL) or the query
        **  times out, check_host() exits immediately with the result
	**  "TempError" 		[draft-ietf-marid-protocol-00.txt, 3.3]
	*/
	
	if (err)
	{
		smf->smf_result = SM_MARID_TEMP_ERROR;
 		sm_marid_check_host_deliver_result(context);
		return;
	}

	/* 
	**  If no matching records are returned, check_host()
	**  exits immediately with the result "None".
	*/

	if (vec_n == 0)
	{
		smf->smf_result = SM_MARID_NONE;
 		sm_marid_check_host_deliver_result(context);
		return;
	}

	/* Find the applicable SPF record. */
	record = NULL;
	for (i = 0; i < vec_n; i++)
	{
		char const	*base;

		if (vec[i] == NULL)
			continue;
		base = sm_marid_check_host_dns_skip_version_tag(
			context, vec[i], strlen(vec[i]));
		if (base == NULL)
			continue;

		/*
		**  Allow duplicates if they are different spf versions.
		**  This simply assumes the dups are adjacent vecs.  That
		**  should be cleaned up, but dups are rare and non-adjacent
		**  dups are even rarer - I have yet to see such a case.
		*/

		if (record != NULL && *(vec[i - 1]) == *(vec[i]))
		{
			sm_marid_log(context, SM_MARID_LOG_FAIL,
				"*** duplicate marid records ***");
			smf->smf_result = SM_MARID_PERM_ERROR;
			sm_marid_check_host_deliver_result(context);
			return;
		}
		record = base;
	}

	if (record == NULL)
	{
		smf->smf_result = SM_MARID_NONE;
 		sm_marid_check_host_deliver_result(context);
		return;
	}

	s = record;
	e = record + strlen(record);

	/*
	**  Duplicate the returned record to allow us to 
	**  delay processing until after recursive invocations.
	*/

	if ((heap = sm_marid_arena_memdup(context, s, e)) == NULL)
	{
		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);
		return;
	}

	smf->smf_record_s = heap;
	smf->smf_record_e = heap + (e - s);

	sm_marid_check_host_record_continue(context);
}

/*
**  SM_MARID_CHECK_HOST_RUN -- check a host's validity.
**
**	Parameters:
**		context -- context initialized with sm_marid_check_host_new()
**
**	Returns:
**		0 if a query has been successfully initiated,
**		EINVAL -- programmer error (e.g. a NULL context)
**		ENOMEM -- we're out of memory.
*/

int
sm_marid_check_host_run(sm_marid *context)
{
	sm_marid_frame 	*smf, *prev;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return EINVAL;

	sm_marid_log(context, SM_MARID_LOG_DEBUG,
		"%*s>>> check-host ip=%s domain=%s sender=%s",
		3 * smf->smf_depth,  "",
		smf->smf_query_ip,
		smf->smf_query_domain,
		smf->smf_query_sender);

	/*
	**  If the <domain> is not an FQDN, the check_host() immediately
	**  returns the result "Fail" and a reason of "Malformed Domain".
	*/

	if (!sm_marid_is_fqdn(context, smf->smf_query_domain))
	{
		smf->smf_result = SM_MARID_FAIL;
		smf->smf_reason = SM_MARID_MALFORMED_DOMAIN;

		sm_marid_check_host_deliver_result(context);
		return 0;
	}

	/*
	**  If we're nested too deeply, return a neutral response.
	*/

	if (  context->sm_depth_max > 0
	   && smf->smf_depth > context->sm_depth_max)
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** more than %lu nested quer%s; "
			"returning neutral result. ***",
			(unsigned long)context->sm_depth_max,
			context->sm_depth_max == 1 ? "y" : "ies") ;

		smf->smf_result = SM_MARID_NEUTRAL;
		sm_marid_check_host_deliver_result(context);

		return 0;
	}

	/*
	**  If we're already in the process of answering the question
	**  that we're asking, return a neutral response.
	*/

	for (prev = smf->smf_prev; prev != NULL; prev = prev->smf_prev)
	{
		if (  strcmp(prev->smf_query_sender, smf->smf_query_sender) == 0
		   && strcmp(prev->smf_query_domain, smf->smf_query_domain) == 0
		   && strcmp(prev->smf_query_ip,     smf->smf_query_ip) == 0)
		{
			sm_marid_log(context, SM_MARID_LOG_FAIL,
 "*** recursive query sender=%s domain=%s ip=%s; returning neutral result. ***",
				smf->smf_query_sender,
				smf->smf_query_domain,
				smf->smf_query_ip);

			smf->smf_result = SM_MARID_NEUTRAL;
			sm_marid_check_host_deliver_result(context);

			return 0;
		}
	}

	/* Let's start by looking up the MARID rules for <domain>. */
	sm_marid_check_host_dns_query(context, SM_MARID_MARID,
		smf->smf_query_domain, sm_marid_check_host_dns_result_marid);
	return 0;
}
