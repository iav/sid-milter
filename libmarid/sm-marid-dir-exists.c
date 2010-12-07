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
sm_marid_dir_exists_c_id[] = "@(#)$Id: sm-marid-dir-exists.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/*
**  SM_MARID_DIR_EXISTS_DNS_RESULT -- handle result of "A" DNS query
**
**	We fail if the query failed, and succeed if it returned
**	anything, anything at all.
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
sm_marid_dir_exists_dns_result(
	sm_marid 		*context,
	int 			err,
	char const * const 	*vec,
	size_t			vec_n)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;

	if (err != 0 || vec_n == 0)
		sm_marid_check_host_record_continue(context);
	else {
		smf->smf_result = smf->smf_prefix;
		if (smf->smf_result == SM_MARID_FAIL)
			smf->smf_reason = SM_MARID_NOT_PERMITTED;
		sm_marid_check_host_deliver_result(context);
	}
}


/*
**  SM_MARID_DIR_EXISTS -- handle an "exists" directive
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_dir_exists(sm_marid *context, sm_marid_expression const *expr)
{
	char const	*tmp;
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return 1;

	/* Expand the value of the right-hand side */
	tmp = sm_marid_domain_spec(context,
		expr->smx_value_s, expr->smx_value_e);
	if (tmp == NULL)
	{
		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);
		return  1;
	}

	/* remember the prefix. */
	smf->smf_prefix = expr->smx_prefix;

	/* Perform a recursive DNS A query on that string. */
	sm_marid_check_host_dns_query(context,
		SM_MARID_A, tmp, sm_marid_dir_exists_dns_result);
	return 1;
}
