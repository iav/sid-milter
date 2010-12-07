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
sm_marid_util_c_id[] = "@(#)$Id: sm-marid-util.c,v 1.3 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/*
**  SM_MARID_MEMSTRCASEEQ -- compare a bunch of bytes and a string
**
**	Parameters:
**		s -- beginning of the bytes we want to compare
**		e -- pointer just after the last byte
**		str -- '\0'-terminated pattern string we're trying to match
**			case insensitively.
**	Returns:
**		0 if the strings are different, 1 if they're the same.
**
*/

int
sm_marid_memstrcaseeq(
	char const	*s,
	char const	*e,
	char const	*str)
{
	for (;;)
	{
		if (*str == '\0')
			return s >= e;
		if (s >= e)
			return 0;
		
		if ( isascii((unsigned char)*s) && isascii((unsigned char)*str)
		   ? tolower(*s) != tolower(*str)
		   : *s != *str)
		   	return 0;

		s++;
		str++;
	}
}
