/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <ctype.h>
#include <string.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_address_c_id[] = "@(#)$Id: sm-marid-address.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

static int
addr_split(
	const char 	*s,
	const char 	*e,
	char const	**mailbox_s,
	char const	**mailbox_e,
	char const	**domain_s,
	char const	**domain_e)
{
	*mailbox_s = NULL;
	*mailbox_e = NULL;
	*domain_s = NULL;
	*domain_e = NULL;

	if (s >= e || s == NULL || e == NULL)
		return 0;

	/* strip the (optional) at-domain-list */
	while (s < e && *s == '@')
	{
		s++;
		if (s < e && *s == '[')
		{
			s++;
			while (*s != '\0' && *s != ']')
				if (*s++ == '\\')
					if (*s++ == '\0')
						return -1;
			if (*s++ != ']')
				return -1;
		}
		else
		{
			while (  s < e
			      && isascii((unsigned char) *s)
			      && (  isalnum(*s)
			         || *s == '.'
				 || *s == '-'))
				s++;
		}
		if (s < e && *s == ',' && s[1] == '@')
			s++;
		else if (s < e && *s == ':' && s[1] != '@')
			s++;
		else
			return -1;
	}

	/*
	**  Now that we're past the source route, save the start of
	**  the 'real' address.
	*/

	*mailbox_s = s;

        /* local-part */
	if (*s == '\"')
	{
		/* skip past the open " */
		s++;
		while (s < e && *s != '\"')
		{
			if (*s == '\\')
			{
				if (s + 1 >= e)
					return -1;
				s++;
			}
			s++;
		}

		if (s >= e)
			return -1;

		/* skip past the close " */
		s++;
	}
	else
	{
		while (s < e && *s != '\0' && *s != '@')
		{
			if (*s == '\\')
			{
				if (s + 1 >= e)
					return -1;
				s++;
			}
			else if (*s <= ' ' || strchr("<>()[],;:\"", *s))
				return -1;
			if (!isascii((unsigned char) *s))
				return -1;
			s++;
		}
	}
	*mailbox_e = s;

        /* @domain */
	if (s >= e || *s != '@')
	{
		*domain_s = NULL;
		*domain_e = NULL;
	}
	else
	{
		++s;

		/* save the beginning of the domain */
		*domain_s = s;

		if (s < e && *s == '[')
		{
			s++;
			while (s < e && *s != ']')
				if (*s++ == '\\')
				{
					if (s >= e)
						return -1;
					s++;
				}
			if (s == *domain_s + 1)
				return -1;
			if (s >= e || *s++ != ']')
				return -1;
		}
		else
		{
			while (  s < e
			     && (  isascii((unsigned char)*s)
			        && (  isalnum(*s)
			           || *s == '.'
			           || *s == '-')))
				s++;

			if (s == *domain_s)
				return -1;
		}
	}

	if (s != e)
		return -1;
	*domain_e = s;
	return 0;
}

int
sm_marid_address_split(sm_marid *context)
{
	sm_marid_frame	*smf;
	char const 	*mbx_s, *dom_s;
	char const 	*mbx_e, *dom_e;

	smf = context->sm_frame;

	if (addr_split(
		smf->smf_query_sender,
		smf->smf_query_sender + strlen(smf->smf_query_sender),
		&mbx_s, &mbx_e, &dom_s, &dom_e))
		return -1;

	if (mbx_s == NULL || mbx_s == mbx_e)
	{
		mbx_s = "postmaster";
		mbx_e = mbx_s + strlen(mbx_s);
	}
	else if (*mbx_s == '"')	/* unquote */
	{
		char *tmp, *w;
		char const *r;
		tmp = sm_marid_arena_memdup(context, mbx_s, mbx_e);
		if (tmp == NULL)
			return -2;
		
		r = tmp + 1;
		w = tmp;

		while (*r != '\0' && *r != '"')
		{
			if (*r == '\\' && r[1] != '\0')
				r++;
			*w++ = *r++;
		}
		*w = '\0';
		mbx_s = tmp;
		mbx_e = tmp + strlen(tmp);
	}

	if (dom_s == NULL)
		dom_e = dom_s = "";
	
	smf->smf_sender_mailbox_s = mbx_s;
	smf->smf_sender_mailbox_e = mbx_e;

	smf->smf_sender_domain_s  = dom_s;
	smf->smf_sender_domain_e  = dom_e;

	return 0;
}
