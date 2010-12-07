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
sm_marid_mod_c_id[] = "@(#)$Id: sm-marid-mod.c,v 1.3 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/*
**  SM_MARID_MOD_IGNORE -- ignore a "default", "accredit",
**	and "match_subdomains" modifier
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_mod_ignore(sm_marid *context, sm_marid_expression const *expr)
{
	(void)context;
	(void)expr;

	/* Continue processing. */
	return 0;
}
