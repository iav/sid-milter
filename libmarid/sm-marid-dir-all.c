/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <stdio.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_dir_all_c_id[] = "@(#)$Id: sm-marid-dir-all.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/* **  SM_MARID_DIR_ALL -- "all" directive; always matches
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_dir_all(sm_marid *context, sm_marid_expression const *expr)
{
	sm_marid_frame	*smf;
	
	smf = context->sm_frame;

	if (expr->smx_value_s != NULL)
	{
		/* syntax error */
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** \"all\" directive with argument? ***");
		smf->smf_result = SM_MARID_PERM_ERROR;
	}
	else
	{
		smf->smf_result = expr->smx_prefix;
		if (smf->smf_result == SM_MARID_FAIL)
			smf->smf_reason = SM_MARID_NOT_PERMITTED;
	}

 	sm_marid_check_host_deliver_result(context);
	return 1;
}
