/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_mod_exp_c_id[] = "@(#)$Id: sm-marid-mod-exp.c,v 1.5 2004/12/02 22:24:39 jutta Exp $";
#endif /* !lint */

/*
**  SM_MARID_MOD_EXP -- handle an "exp" modifier
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
sm_marid_mod_exp(sm_marid *context, sm_marid_expression const *expr)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return 1;
	/*
	**  There can be only one exp modifier; syntax error if
	**  this isn't the first.
	*/

	if (smf->smf_exp_s != NULL)
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** more than one exp modifier ***");

		smf->smf_result = SM_MARID_PERM_ERROR;
		sm_marid_check_host_deliver_result(context);
		return 1;
	}

	/* Remember our destination. */
	smf->smf_exp_s = expr->smx_value_s;
	smf->smf_exp_e = expr->smx_value_e;

	/*
	**  Continue processing.  Exp is only executed if something fails.
	**  If the result of this frame turns out to be FAIL, 
	**  sm_marid_mod_exp_execute() will be called by the code
	**  that returns the frame result.
	*/

	return 0;
}

/*
**  SM_MARID_MOD_EXP_EXECUTE_DNS_RESULT -- execute an earlier "exp" modifier.
**
**	Parameters:
**		context -- calling context
**
**	Returns:
**		none
*/

static void
sm_marid_mod_exp_execute_dns_result(
	sm_marid 	*context,
	int 		err,
	char const * const *vec,
	size_t		vec_n)
{
	size_t		need, i;
	char		*tmp, *w;
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;
	/*
	**  If there are any processing errors, temporary (such as
	**  SERVFAIL) or permanent (such as NXDOMAIN), or if no records are
   	**  returned, or if more than one record is returned, then the
   	**  explanation string empty with no further computation.
	*/

	if (err != 0 || vec_n == 0 || vec == NULL)
	{
		smf->smf_explanation = "";
		sm_marid_check_host_deliver_result(context);
		return;
	}

	/* concatenate the text records. */
	need = 0;
	for (i = 0; i < vec_n; i++)
		if (vec[i] != NULL)
			need += strlen(vec[i]);
	need++;
	if ((tmp = sm_marid_arena_alloc(context, need)) == NULL)
	{
		smf->smf_explanation = "";
		sm_marid_check_host_deliver_result(context);
		return;
	}
	w = tmp;
	for (i = 0; i < vec_n; i++)
	{
		char const *r;
		if ((r = vec[i]) == NULL)
			continue;
		while ((*w = *r++) != '\0')
			w++;
	}
	*w = '\0';

	/* evaluate that and use the result as explanation. */
	tmp = sm_marid_evaluate(context, tmp, tmp + strlen(tmp), 1);
	smf->smf_explanation = (tmp == NULL ? "" : tmp);

	sm_marid_check_host_deliver_result(context);
}

/*
**  SM_MARID_MOD_EXP_EXECUTE -- execute an earlier exp
**
**	An earlier execution may have stored an exp request; now
**  	we're actually using it as part of executing a failure.
**
**	Parameters:
**		context -- calling context
**
**	Returns:
**		none
*/

void
sm_marid_mod_exp_execute(sm_marid *context)
{
	char		*tmp;
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;

	smf->smf_result = SM_MARID_FAIL;

	/* If no exp modifier is present, the empty string is returned. */
	if (smf->smf_exp_s == NULL)
	{
		smf->smf_explanation = "";
		sm_marid_check_host_deliver_result(context);
		return;
	}

	/* Expand the value of the right-hand side */
	tmp = sm_marid_evaluate(context, smf->smf_exp_s, smf->smf_exp_e, 0);
	if (tmp == NULL)
	{
		smf->smf_explanation = "";
		sm_marid_check_host_deliver_result(context);
		return;
	}

	/* Perform a DNS TXT query on that string. */
	sm_marid_check_host_dns_query(context,
		SM_MARID_TXT, tmp, sm_marid_mod_exp_execute_dns_result);
}
