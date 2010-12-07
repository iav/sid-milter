/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <ctype.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_mod_redirect_c_id[] = "@(#)$Id: sm-marid-mod-redirect.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/*
**  SM_MARID_MOD_REDIRECT -- handle a redirect modifier
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		0 normally, to continue processing;
**		nonzero in case of allocation, usage, or
**		syntax errors that deliver a result.
*/

int
sm_marid_mod_redirect(sm_marid *context, sm_marid_expression const *expr)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return 1;

	/* There can be only one redirect modifier -- this isn't the first */
	if (smf->smf_redirect_s != NULL)
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** more than one redirect modifier ***");

		smf->smf_result = SM_MARID_PERM_ERROR;
		sm_marid_check_host_deliver_result(context);
		return 1;
	}

	/* Remember our destination. */
	smf->smf_redirect_s = expr->smx_value_s;
	smf->smf_redirect_e = expr->smx_value_e;

	/*
	**  Continue processing.  Redirect is only executed
	**  if nothing else matches.
	*/

	return 0;
}

/*
**  SM_MARID_MOD_REDIRECT_EXECUTE_RESULT -- receive redirect result.
**
**	Parameters:
**		context -- calling context
**		red -- frame from the redirect
**
**	Returns:
**		none
*/

static void
sm_marid_mod_redirect_execute_result(
	sm_marid 		*context,
	sm_marid_frame const 	*red)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;

	smf->smf_result 	= red->smf_result;
	smf->smf_reason 	= red->smf_reason;
	smf->smf_explanation 	= red->smf_explanation;

	/*
	**  Don't try to retrieve an explanation for this one -- the 
	**  previous context already did that, if any.
	*/

	smf->smf_exp_tried 	= 1;

	sm_marid_check_host_deliver_result(context);
}

/*
**  SM_MARID_MOD_REDIRECT_EXECUTE -- execute an earlier redirect
**
**	An earlier execution stored a redirect request; now
**  	we're actually executing it.
**
**	Parameters:
**		context -- calling context
**
**	Returns:
**		none
*/

void
sm_marid_mod_redirect_execute(sm_marid *context)
{
	char		*tmp;
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;

	/*
	**   If none of the mechanisms match and there is no redirect modifier,
	**   then the check_host() exists with a result of "Neutral".
	*/

	if (smf->smf_redirect_s == NULL)
	{
		smf->smf_result = SM_MARID_NEUTRAL;
		sm_marid_check_host_deliver_result(context);

		return;
	}

	/*
	**   If there is a redirect modifier, check_host() proceeds as
	**   defined in section 5.1.
	*/

	/* Expand the value of the right-hand side */
	tmp = sm_marid_evaluate(context,
		smf->smf_redirect_s,
		smf->smf_redirect_e, 0);
	if (tmp == NULL)
	{
		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);

		return;
	}

	/* Recurse, reusing the old ip and sender, but with the new domain. */
	if (sm_marid_check_host_frame(context,
		smf->smf_query_ip, tmp, smf->smf_query_sender,
		sm_marid_mod_redirect_execute_result) == NULL)
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** failed to allocate frame for recursion ***");

		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);
	}

	if (sm_marid_check_host_run(context))
	{
		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);
	}
}
