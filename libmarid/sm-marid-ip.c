/*
**  Copyright (c) 2004, 2005 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <ctype.h>
#include <limits.h>
#include <stdio.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_ip_c_id[] = "@(#)$Id: sm-marid-ip.c,v 1.6 2005/12/08 21:52:32 msk Exp $";
#endif /* !lint */

/*
**  SM_MARID_IP_VERSION -- is this ipv4 or ipv6?  
**
**	Parameters:
**		ip_s -- in: the textual IP address
**		ip_e -- in: end of the textual IP address
**
**	Returns:
**		0 if this isn't an IP address,
**		'4' if it's IPV4, '6' if it's IPV6.
*/

int
sm_marid_ip_version(char const *ip_s, char const *ip_e)
{
	size_t		ndots;
	char const	*p;
	if (ip_s == NULL || ip_e == NULL || ip_s == ip_e)
		return 0;

	for (ndots = 0, p = ip_s; p < ip_e; p++)
		if (*p == '.')
			ndots++;
		else if (isascii((unsigned char)*p) && !isdigit(*p))
			return '6';

	if (ndots <= 3)
		return '4';
	return '6';
}

/*
**  SM_MARID_IP_CANON -- transform a written IP address into a byte string
**
**	Parameters:
**		ip_s -- in: the textual IP address
**		ip_e -- in: end of the textual IP address
**		bytes_out -- out: store bytes here.
**		n_out -- in: how much space we have; out: occupied space.
**
**	Returns:
**		0 on success, an error on syntax error.
*/

int
sm_marid_ip_canon(
	char const	*ip_s,
	char const	*ip_e,
	unsigned char	*bytes_out,
	size_t		*n_out)
{
	size_t		n;
	size_t		ndots;
	char const	*p;

	/* XXX */



	if (ip_s == NULL || ip_e == NULL || ip_s == ip_e || *n_out < 4)
	{
		*n_out = 0;
		return 0;
	}
	
	n = *n_out;
	*n_out = 0;

	for (ndots = 0, p = ip_s; p < ip_e; p++)
		if (*p == '.')
			ndots++;

	if (ndots <= 3)
	{
		unsigned long	val;

		p = ip_s;
		for (;;)
		{
			val = 0;
			if (!(isascii(*p) && isdigit(*p)))
				return -1;

			while (isascii(*p) && isdigit(*p) && p < ip_e)
			{
				val *= 10;
				val += *p - '0';
				p++;
			}
			if (p >= ip_e)
				break;

			if (*p != '.')
				return -1;
			p++;

			bytes_out[ (*n_out)++ ] = val;
		}

		switch (*n_out)
		{
		  case 0:
			bytes_out[(*n_out)++] = 0xFF & (val >> 24);
		  case 1:
			bytes_out[(*n_out)++] = 0xFF & (val >> 16);
		  case 2:
			bytes_out[(*n_out)++] = 0xFF & (val >> 8);
		  case 3:
			bytes_out[(*n_out)++] = 0xFF & val;
			break;
		}
		return 0;
	}
	/* XXX */
	return 0;
}

/*
**  SM_MARID_IP_EQ -- compare top bits of two ip addresses for equality
**
**	Parameters:
**		a -- bytes of the first address
**		b -- bytes of the second address
**		n -- # of bytes in both
**		bits -- # of bits to compare
**
**	Returns:
**		1 if they match, 0 if they don't.
*/

int
sm_marid_ip_eq(
	unsigned char const	*a,
	unsigned char const	*b,
	size_t			n,
	size_t			bits)
{
	size_t			i = 0;

	if (a == NULL && b == NULL)
		return 1;
	if (a == NULL || b == NULL)
		return 0;

	while (bits >= 8 && i < n)
	{
		if (*a++ != *b++)
			return 0;
		i++;
		bits -= 8;
	}

	if (bits == 0 || i >= n)
		return 1;

	return  ((*a ^ *b) >> (CHAR_BIT - bits)) == 0;
}
