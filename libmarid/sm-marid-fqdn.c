/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <stdio.h>
#include <ctype.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_fqdn_c_id[] = "@(#)$Id: sm-marid-fqdn.c,v 1.5 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */


/*
**  SM_MARID_IS_FQDN -- is this a fully-qualified domain name, syntactically?
**
**	We're using the definition from RFC 2821:
**
**	      Domain = (sub-domain 1*("." sub-domain)) [...]
**	      sub-domain = Let-dig [Ldh-str]
**	      Let-dig = "_" / ALPHA / DIGIT
**	      Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig
**
**	Parameters:
**		s -- the string to test
**
**	Returns:
**		1 if the parameter is a fully-qualified domain name,
**		0 if it isn't.
*/

#define	FQDN_ISLETDIG(s)	\
		(isascii((unsigned char)(s)) && (isalnum(s) || (s) == '_'))

int
sm_marid_is_fqdn(sm_marid *context, char const *s)
{
	int	saw_dot = 0;

	if (s == NULL || *s == '\0')
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** domain is %s ***",
			s == NULL ? "null" : "empty");
		return 0;
	}

	for (;;)
	{
		if (!FQDN_ISLETDIG(*s))
		{
			sm_marid_log(context, SM_MARID_LOG_FAIL,
				"*** domain segment starts with '%c', which "
				"is not a letter or digit ***", *s);
			return 0;
		}
		s++;
		while (*s != '\0' && *s != '.')
		{
			if (*s != '-' && !FQDN_ISLETDIG(*s))
			{
				sm_marid_log(context, SM_MARID_LOG_FAIL,
					"*** domain segment contains '%c', "
					"which is not a letter, digit, or "
					"- ***", *s);
				return 0;
			}
			s++;
		}
		if (!FQDN_ISLETDIG(s[-1]))
		{
			sm_marid_log(context, SM_MARID_LOG_FAIL,
				"*** domain segment ends in '%c', "
				"which is not a letter or digit", *s);
			return 0;
		}
		if (*s == '\0')
		{
			if (!saw_dot)
				sm_marid_log(context, SM_MARID_LOG_FAIL,
					"*** fully qualified domain "
					"must contain at least one \".\" ***");
			return saw_dot;
		}
		saw_dot = 1;
		s++;
	}
}
