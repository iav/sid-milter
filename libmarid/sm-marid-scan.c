/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <ctype.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_scan_c_id[] = "@(#)$Id: sm-marid-scan.c,v 1.3 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

#define SM_MARID_IS_DIRECTIVE_PREFIX(x)	\
	((x) == '+' || (x) == '-' || (x) == '?' || (x) == '~')

#define	SM_MARID_IS_ALPHA(x)		\
	(isascii((unsigned char)(x)) && isalpha(x))

#define	SM_MARID_IS_ALNUM(x)		\
	(isascii((unsigned char)(x)) && isalnum(x))

#define	SM_MARID_IS_DIGIT(x)		\
	(isascii((unsigned char)(x)) && isdigit(x))

static char const *
name_end(char const *s, char const *e)
{
	if (s >= e)
		return NULL;
	if (!SM_MARID_IS_ALPHA(*s))
		return NULL;
	s++;
	while (s < e)
	{
		if (  !SM_MARID_IS_ALNUM(*s)
		   && *s != '-' 
		   && *s != '_'
		   && *s != '.')
		   	break;
		s++;
	}
	return s;
}

/*
**  SM_MARID_SCAN_EXPRESSION -- parse a directive or modifier into parts.
**
**     directive   = [ prefix ] mechanism
**     prefix      = "+" / "-" / "?" / "~"
**     mechanism   = name [ ":" macro-string ] *[ "/" *DIGIT ]
**     name        = alpha *( alpha / digit / "-" / "_" / "." )
**     macro-string = *( macro-char / VCHAR )
**     macro-char   = ( "%{" ALPHA transformer *delimiter "}" )
**  	                 / "%%" / "%_" / "%-"
**     VCHAR	   = %x21-7E
**
**     modifier    = redirect / explanation / unknown-modifier
**     redirect    = "redirect" "=" domain-spec
**     explanation = "exp" "=" domain-spec
**     unknown-modifier = name "=" macro-string
** 
**     domain-spec  = domain-name / macro-string
**     domain-name  = domain-part *( "." domain-part ) [ "." ]
**     domain-part  = as defined in [RFC 1034]
** 
**     ip4-network  = as per conventional dotted quad notation,
*/

int
sm_marid_scan_expression(
	char const		**s_inout,
	char const		*e,
	sm_marid_expression	*expr_out)
{
	char const		*s, *x;

	s = *s_inout;

	/* skip leading spaces. */
	while (s < e && *s == ' ')
		s++;

	/* fast forward to this term's end. */
	for (x = s; x < e && *x != ' '; x++)
		;

	if (s < e && SM_MARID_IS_DIRECTIVE_PREFIX(*s))
		expr_out->smx_prefix = *s++;
	else
	{
		char const *p;

		/* This might be a modifier, not a mechanism.  Check. */
		if ((p = name_end(s, e)) != NULL && p < e && *p == '=')
		{
			expr_out->smx_type 	= SM_MARID_MODIFIER;
			expr_out->smx_name_s 	= s;
			expr_out->smx_name_e 	= p;
			expr_out->smx_value_s 	= p + 1;
			expr_out->smx_value_e 	= x;

			while (x < e && *x == ' ')
				x++;
			*s_inout = x;
			return 0;
		}

		/* The default prefix value is + */
		expr_out->smx_prefix = '+';
	}
	expr_out->smx_type = SM_MARID_DIRECTIVE;

	expr_out->smx_name_s = s;
	expr_out->smx_name_e = s = name_end(s, e);
	expr_out->smx_value_s = NULL;
	expr_out->smx_value_e = NULL;
	expr_out->smx_cidr_s = NULL;
	expr_out->smx_cidr_e = NULL;

	if (s == NULL)
	{
		*s_inout = e;
		return -1;
	}

	if (s < e && *s == ':')
	{
		expr_out->smx_value_s = s + 1;
		expr_out->smx_value_e = x;
	}
	else
	{
		if (s < x)
		{
			if (*s != '/')
			{
				*s_inout = e;
				return -1;
			}
			expr_out->smx_cidr_s = s;
			for (;;)
			{
				s++;
				if (s >= x || !SM_MARID_IS_DIGIT(*s))
				{
					*s_inout = e;
					return -1;
				}
				while (s < x && SM_MARID_IS_DIGIT(*s))
					s++;
				if (s == x)
					break;
				if (*s != '/')
				{
					*s_inout = e;
					return -1;
				}
			}
			expr_out->smx_cidr_e = s;
			s = x;
		}
	}

	while (x < e && *x == ' ')
		x++;
	*s_inout = x;
	return 0;
}

/*
**  SM_MARID_SCAN_CIDR -- scan optional trailing bit lengths
**
**	The end of a value may contain one or two bit lengths.
**	Parse them and adjust the value to not contain them.
**
**	Parameters:
**		s -- beginning of the value	
**		e_inout -- adjustable end of the value	
**		i4_out -- if non-NULL, store i4 bit length here
**		i6_out -- if non-NULL, store i6 bit length here
**	Returns:
**		0 on success, nonzero on syntax error
*/

int
sm_marid_scan_cidr(
	char const		*s,
	char const		**e_inout,
	size_t			*i4_out,
	size_t			*i6_out)
{
	char const		*e = *e_inout;

	if (i4_out != NULL)
		*i4_out = 32;
	if (i6_out != NULL)
		*i6_out = 128;

	for (;;)
	{
		unsigned long mul = 1;
		unsigned long val = 0;

		if (  (i4_out == NULL && i6_out == NULL)
		   || e <= s
		   || !isascii((unsigned char)e[-1])
		   || !isdigit(e[-1]))
		{
			*e_inout = e;
			return 0;
		}

		/* Scan a number up to a / */
		while (e > s && e[-1] != '/')
		{
			if (isascii((unsigned char)e[-1]) && isdigit(e[-1]))
			{
				val += (e[-1] - '0') * mul;
				mul *= 10;

				e--;
			}
			else
				return 0;
		}
		if (e <= s)
			return 0;
		e--;
		if (e > s && e[-1] == '/' && i4_out != NULL && i6_out != NULL)
		{
			e--;
			*i6_out = val;
			i6_out = NULL;
		}
		else
		{
			*(i4_out != NULL ? i4_out : i6_out) = val;
			break;
		}
	}
	*e_inout = e;
	return 0;
}

