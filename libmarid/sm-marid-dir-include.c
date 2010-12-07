/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_dir_include_c_id[] = "@(#)$Id: sm-marid-dir-include.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/*
**  SM_MARID_DIR_INCLUDE_EXECUTE_RESULT -- receive include result.
**
**	Parameters:
**		context -- calling context
**		data -- our opaque data pointer, the previous context.
**		frame -- the result returned to us.
**
**	Returns:
**		none
*/

static void
sm_marid_dir_include_execute_result(
	sm_marid 		*context,
	sm_marid_frame const 	*inc_smf)
{
	sm_marid_frame *smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;

   	/*
	**  This mechanism matches when the recursive check_host() result
	**  returns a "Pass", and doesn't match when the result is "Fail",
	**  "SoftFail", or "Neutral".
	**
	**  If the result is "TempError", "PermError" or "None", then
	**  processing of the current check_host() stops immediately and returns
	**  either "TempError" in the first case, or "PermError" in the second
   	**  two.
	*/

	switch (inc_smf->smf_result)
	{
	  default:
	  	sm_marid_log(context, SM_MARID_LOG_WARN, 
			"%s:%d: unexpected smf_result %d",
			__FILE__, __LINE__, (int)inc_smf->smf_result);
		return;

	  case SM_MARID_PASS:
	  	/* matches. */
		smf->smf_result = smf->smf_prefix;
	  	if (smf->smf_result == SM_MARID_FAIL)
	  		smf->smf_reason = SM_MARID_NOT_PERMITTED;
		break;

	  case SM_MARID_FAIL:
	  case SM_MARID_SOFT_FAIL:
	  case SM_MARID_NEUTRAL:
	  	sm_marid_check_host_record_continue(context);
		return;

	  case SM_MARID_TEMP_ERROR:
	  	/* temp error; pass it on */
		smf->smf_result 	= inc_smf->smf_result;
		smf->smf_reason 	= inc_smf->smf_reason;
		smf->smf_explanation 	= inc_smf->smf_explanation;
		break;

	  case SM_MARID_NONE:
	  case SM_MARID_PERM_ERROR:
	  	/* perm error */
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** \"include\" failed ***");

		smf->smf_result = SM_MARID_PERM_ERROR;
		break;
	}

	sm_marid_check_host_deliver_result(context);
}


/*
**  SM_MARID_DIR_INCLUDE -- handle an include directive
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_dir_include(sm_marid *context, sm_marid_expression const *expr)
{
	char const	*tmp;
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return 1;

	tmp = sm_marid_domain_spec(
		context,
		expr->smx_value_s,
		expr->smx_value_e);
	if (tmp == NULL)
	{
		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);

		return 1;
	}

	/* remeber the prefix */
	smf->smf_prefix = expr->smx_prefix;

	/* Allocate a new context with the new domain. */
	smf = sm_marid_check_host_frame(context,
		smf->smf_query_ip, tmp, smf->smf_query_sender,
		sm_marid_dir_include_execute_result);
	if (smf == NULL)
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** failed to allocate subframe for \"include\" ***");

		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);

		return 1;
	}

	/* Recurse, reusing the old ip and sender, but with the new domain. */
	if (sm_marid_check_host_run(context))
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** failed to run check-host for \"include\" ***");

		smf->smf_result = SM_MARID_PERM_ERROR;
		sm_marid_check_host_deliver_result(context);
	}
	return 1;
}
