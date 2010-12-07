/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_dns_c_id[] = "@(#)$Id: sm-marid-dns.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/*
**  SM_MARID_CHECK_HOST_DNS_QUERY -- execute a DNS query
**
**	This function is called by functions from the marid
**	library to execute DNS queries.  The caller then
**	returns, and its caller returns, and so on, all
**	the way up to the application.
**
**	Parameters:
**		context -- the sm_marid context for the whole query
**		domain -- domain we looked up
**		type -- what information do we want about it?
**		result_handler -- call this callback with the response
**
**	Returns:
**		none.
*/

void
sm_marid_check_host_dns_query(
	sm_marid			*context,
	int				type,
	char const			*domain,
	sm_marid_dns_result_callback	*result_handler)
{
	context->sm_request_n++;

	if (  context->sm_request_max > 0
	   && context->sm_request_n > context->sm_request_max)
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** failing %lu%s application query; "
			"maximum allowed: %lu ***",
			(unsigned long)context->sm_request_n,
			  (context->sm_request_n == 1 ? "st"
			: (context->sm_request_n == 2 ? "nd"
			: (context->sm_request_n == 3 ? "rd" : "th"))),
			(unsigned long)context->sm_request_max);

		(* result_handler)(context, SM_MARID_ERR_MISC, NULL, 0);
		return;
	}

	context->sm_dns_type   = type;
	context->sm_dns_domain = sm_marid_arena_memdup(
		context, domain, domain + strlen(domain));
	context->sm_dns_result = result_handler;
}


/*
**  SM_MARID_CHECK_HOST_DNS_SKIP_MARID_PATTERN -- skip past identifier pattern
**
**	Parameters:
**		context -- calling context
**		s -- pointer to (presumed) marid record text
**		n -- # of bytes pointed to by <s>
**		pattern -- pattern string to skip.
**
**	Returns:
**		NULL if the input doesn't match the pattern;
**		otherwise a pointer just past the pattern in the input.
*/

static char *
sm_marid_check_host_dns_skip_marid_pattern(
	sm_marid		*context,
	char const 		*s,
	size_t			n,
	char const		*pattern)
{
	char const		*p = pattern;

	while (n > 0)
	{
		if (*p == '%')
		{
			p++;
			switch (*p++)
			{
			  case '%':
			  	/* literal % */
				if (*s != '%')
				{
					return NULL;
				}
				s++, n--;
				break;

			  case ',':
			  	/* comma+continue or [space]+end */
				if (*s == ' ')
					return (char *)(s + 1);
				else if (*s != ',')
				{
					return NULL;
				}
				s++, n--;
				break;

			  case 'v':
			  	/* *VCHAR */
			  	while (n > 0 && *s >= 0x21 && *s <= 0x7E)
					s++, n--;
				break;

			  case 'd':
			  	/* 1*DIGIT */
			  	if (!isascii(*s) || !isdigit(*s))
				{
					return NULL;
				}
			  	while (n > 0 && isascii(*s) && isdigit(*s))
					s++, n--;
				break;

			  default:
				/* Bad pattern! */
				sm_marid_log(context, SM_MARID_LOG_WARN,
					"*** unexpected escape sequence "
					"\"%%%c\" in marid version \"%s\"",
					p[-1], pattern);
			  	return NULL;
			}
		}
		else
		{
			if (*p == '\0' && *s == ' ')
				return (char *)(s + 1);
			else if ((isascii(*s) ? tolower(*s) : *s) != *p++)
				return NULL;

			s++, n--;
		}
	}

	if (*p == '\0' || (p[0] == '%' && p[1] == ','))
		return (char *)s;

	return NULL;
}

/*
**  SM_MARID_CHECK_HOST_DNS_IS_MARID -- is this a MARID record?
**
**	Parameters:
**		context -- calling context
**		s -- pointer to (presumed) marid record text
**		n -- # of bytes pointed to by <s>
**
**	Returns:
**		none
*/

int
sm_marid_check_host_dns_is_marid(
	sm_marid	*context,
	char const 	*s,
	size_t		n)
{
	char const * const *pat;

	for (pat = context->sm_version_patterns;
	     pat != NULL && *pat != NULL;
	     pat++)

	     	if (sm_marid_check_host_dns_skip_marid_pattern(
			context, s, n, *pat) != NULL)
			return 1;
	return 0;
}

/*
**  SM_MARID_CHECK_HOST_DNS_SKIP_VERSION_TAG -- point past MARID record.
**
**	Parameters:
**		context -- calling context
**		s -- pointer to (presumed) marid record text
**		n -- # of bytes pointed to by <s>
**
**	Returns:
**		none
*/

char *
sm_marid_check_host_dns_skip_version_tag(
	sm_marid	*context,
	char const 	*s,
	size_t		n)
{
	char const * const *pat;
	char 		*ptr;

	for (pat = context->sm_version_patterns;
	     pat != NULL && *pat != NULL;
	     pat++)
	{
	     	ptr = sm_marid_check_host_dns_skip_marid_pattern(
			context, s, n, *pat);
		if (ptr != NULL)
			return ptr;
	}
	return 0;
}
