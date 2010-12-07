/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <string.h>
#include <ctype.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_dir_ptr_c_id[] = "@(#)$Id: sm-marid-dir-ptr.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/*
**  SM_MARID_DIR_PTR_DNS_RESULT -- handle result of DNS query for "ptr"
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
sm_marid_dir_ptr_dns_result(
	sm_marid 		*context,
	int 			err,
	char const * const 	*vec,
	size_t			vec_n)
{
	size_t			i;
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;

	if (err == 0)
	{
		char const	*tmp;

		/* Expand the target value */
		tmp = sm_marid_domain_spec(context,
			smf->smf_value_s, smf->smf_value_e);
		if (tmp == NULL)
		{
			smf->smf_result = SM_MARID_TEMP_ERROR;
			sm_marid_check_host_deliver_result(context);
			return;
		}

		for (i = 0; i < vec_n; i++)
		{
			if (sm_marid_domain_contains_or_is(tmp, vec[i]))
			{
				smf->smf_result
					= smf->smf_prefix;
				if (  smf->smf_result
				   == SM_MARID_FAIL)
					smf->smf_reason
						= SM_MARID_NOT_PERMITTED;
				sm_marid_check_host_deliver_result(context);
				return;
			}
		}
	}
	sm_marid_check_host_record_continue(context);
}

/*
**  SM_MARID_DIR_PTR -- handle a "ptr" directive
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_dir_ptr(sm_marid *context, sm_marid_expression const *expr)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return 1;

	/* remember the prefix. */
	smf->smf_prefix = expr->smx_prefix;

	/* remember the target value. */
	if (expr->smx_value_s != NULL && expr->smx_value_e != NULL)
	{
		smf->smf_value_s = sm_marid_arena_memdup(context,
			expr->smx_value_s,  expr->smx_value_e);
		if (smf->smf_value_s == NULL)
		{
			smf->smf_result = SM_MARID_TEMP_ERROR;
			sm_marid_check_host_deliver_result(context);
			return 1;
		}
		smf->smf_value_e = smf->smf_value_s
			+ (expr->smx_value_e - expr->smx_value_s);
	}
	else
	{
		smf->smf_value_s = NULL;
		smf->smf_value_e = NULL;
	}

	/* Perform a recursive DNS PTR query on the IP. */
	sm_marid_check_host_dns_query(context,
		SM_MARID_PTR,
		smf->smf_query_ip,
		sm_marid_dir_ptr_dns_result);
	return 1;
}
