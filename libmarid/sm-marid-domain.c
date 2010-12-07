/*
**  Copyright (c) 2004, 2005 Sendmail, Inc. and its suppliers.
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
sm_marid_domain_c_id[] = "@(#)$Id: sm-marid-domain.c,v 1.6 2005/12/08 21:52:32 msk Exp $";
#endif /* !lint */

/*
**  SM_MARID_DOMAIN_SPEC -- get the domain
**
**	Parameters:
**		context -- calling context
**		domain_s -- NULL or beginning of domain expression
**		domain_e -- NULL or end of domain expression
**
**	Returns:
**		none
*/

char const *
sm_marid_domain_spec(
	sm_marid 	*context,
	char const	*domain_s,
	char const	*domain_e)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return NULL;
	/*
	**  If the <domain-spec> is present, then it is macro expanded (see
	**  Section 7) and becomes the <target-name>.  If the <domain-spec> is
	**  not provided, the <domain> is used as the <target-name>.
	*/

	if (domain_s != NULL && domain_e != NULL)
		return sm_marid_evaluate(context, domain_s, domain_e, 0);
	else
		return smf->smf_query_domain;
}

/*
**  SM_MARID_DOMAIN_CONTAINS_OR_IS -- is <suffix> all or a suffix of <domain>?
**	
**	Parameters:
**		suffix -- suffix 
**		domain -- possible subdomain 
**
**	Returns:
**		1 if <suffix> is <domain> or a container of <domain>
**		0 otherwise.
*/

int
sm_marid_domain_contains_or_is(char const *suffix, char const *domain)
{
	char const	*domain_end;
	size_t		suffix_n;

	suffix_n = strlen(suffix);
	domain_end = domain + strlen(domain);

	if (domain_end - domain < suffix_n)
		return 0;
	if (!sm_marid_memstrcaseeq(
		suffix,
		suffix + suffix_n,
		domain_end - suffix_n))
		return 0;

	return    domain_end - domain == suffix_n
	       || domain_end[-suffix_n - 1] == '.';
}
