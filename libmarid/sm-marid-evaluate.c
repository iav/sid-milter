/*
**  Copyright (c) 2004, 2005 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_evaluate_c_id[] = "@(#)$Id: sm-marid-evaluate.c,v 1.7 2005/12/08 22:27:51 msk Exp $";
#endif /* !lint */

#define	MARID_IS_URL_MARK(x)	\
	(  (x) == '-' || (x) == '_' || (x) == '.' || (x) == '!'	\
	|| (x) == '~' || (x) == '*' || (x) == '\'' || (x) == '(' || (x) == ')')

#define	MARID_IS_DELIM(x)	\
	(  (x) == '.' || (x) == '-' || (x) == '+' || (x) == ','	\
	|| (x) == '/' || (x) == '_' || (x) == '=')

static char const *
seq_end(char const *s, char const *e)
{
	if (s >= e)
		return NULL;
	if (*s != '{')
		return NULL;
	s++;
	if (s >= e)
		return NULL;
	if (!isascii((unsigned char)*s) || !isalpha(*s))
		return NULL;
	s++;
	while (s < e && isascii(*s) && isdigit(*s))
		s++;
	if (s < e && (*s == 'r' || *s == 'R'))
		s++;
	while (s < e && MARID_IS_DELIM(*s))
		s++;
	if (s >= e || *s != '}')
		return NULL;
	return s + 1;
}

static int
sm_marid_evaluate_token(
	char const **s, char const *e, char const **tok_s, char const **tok_e)
{
	char const	*p;

	if (*s >= e)
		return 0;
	
	if (**s != '%')
	{
		*tok_s = *s;
		if ((p = memchr(*s, '%', e - *s)) == NULL)
			p = e;
		*s = *tok_e = p;
		return '.';
	}

	if (   *s + 1 < e 
	   && (  (*s)[1] == '%'
	      || (*s)[1] == '_'
	      || (*s)[1] == '-'))
	{
		*tok_s = *s;
		*tok_e = *s += 2; 

		return (*s)[-1];
	}

	if ((p = seq_end(*s + 1, e)) != NULL)
	{
		*tok_s = *s;
		*tok_e = p;

		*s = p;
		return (*tok_s)[2];
	}

	*tok_s = *s;
	*tok_e = *s + 1;

	(*s)++;
	return '%';
}

static int
sm_marid_evaluate_variable_string(
	sm_marid	*context,
	int		var,
	char const	**s_out,
	char const	**e_out,
	char const 	*timestamp_buf)
{
	int 		err;
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return EINVAL;

	if (!isascii(var))
	{
		*s_out = "unknown";
		*e_out = *s_out + strlen(*s_out);

		return 0;
	}

	*e_out = NULL;
	switch (tolower(var))
	{
	  case 's':
	  	*s_out = smf->smf_query_sender;
		break;
	
	  case 'l':
		if (  smf->smf_sender_mailbox_s == NULL 
		   || smf->smf_sender_mailbox_e == NULL)
			if ((err = sm_marid_address_split(context)) != 0)
				return err;
		*s_out = smf->smf_sender_mailbox_s;
		*e_out = smf->smf_sender_mailbox_e;
		break;
	
	  case 'o':
		if (  smf->smf_sender_domain_s == NULL 
		   || smf->smf_sender_domain_e == NULL)
			if ((err = sm_marid_address_split(context)) != 0)
				return err;
		*s_out = smf->smf_sender_domain_s;
		*e_out = smf->smf_sender_domain_e;
		break;
	
	  case 'd':
	  	*s_out = smf->smf_query_domain;
	  	break;
	
	  case 'i':
	  	*s_out = smf->smf_query_ip;
		break;
	
	  case 'v':
		*s_out = (sm_marid_ip_version(
	  		smf->smf_query_ip,
	  		smf->smf_query_ip
			 + strlen(smf->smf_query_ip)) == '6')
			? "ipv6" : "in-addr";
		break;
	  case 'c':
	  	*s_out = context->sm_smtp_client_ip;
		break;
	  case 'r':
	  	*s_out = context->sm_smtp_hostname;
		if (*s_out == NULL || **s_out == '\0')
			*s_out = "unknown";
		break;
	  case 't':
		*s_out = timestamp_buf;
		break;

	  case 'p':
	  case 'h':
	  	*s_out = "deprecated";
		break;

	  default:
	  	*s_out = "unknown";
		break;
	}

	if (*e_out == NULL && *s_out != NULL)
		*e_out = *s_out + strlen(*s_out);
	return 0;
}

static void
mark_separators(unsigned char *bitarray, char const *s)
{
	memset(bitarray, 0, (1 << CHAR_BIT) / 8);

	while (*s != '}')
	{
		bitarray[(unsigned char)*s / 8] |= 1 << ((unsigned char)*s % 8);
		s++;
	}
}

static int
get_chunk(
	char const 		**s,
	char const		**e,
	char const 		**chunk_s,
	char const 		**chunk_e,
	int			backwards,
	unsigned char const 	*separators)
{
	char const 		*p;

#	define	IS_SEP(b, s)		\
		((b)[(unsigned char)(s) / 8] & (1 << ((unsigned char)(s) % 8)))

	if (*s >= *e)
		return 0;

	if (backwards)
	{
		*chunk_e = *e;
		if (IS_SEP(separators, (*e)[-1]))
		{
			if ((*e - *s) > 1)
				p = *e - 2;
			else
				return 0;
		}
		else
		{
			p = *e - 1;
		}

		for (; p > *s; p--)
		{
			if (IS_SEP(separators, p[-1]))
				break;
		}

		*chunk_s = *e = p;
	}
	else
	{
		*chunk_s = *s;
		if (IS_SEP(separators, **s))
			p = *s + 1;
		else
			for (p = *s; p < *e; p++)
				if (IS_SEP(separators, *p))
					break;
		*chunk_e = *s = p;
	}
	return 1;
}

/*
**  SM_MARID_EVALUTE -- expand a macro.
**
**	Parameters:
**		context - context to evaluate in
**		s -- beginning of macro text
**		e -- end of macro text
**
**	Returns:
**		the expanded macro, or NULL in case of
**		programmer or allocation errors.
*/

char *
sm_marid_evaluate(sm_marid *context, char const *s, char const *e, int flag_exp)
{
	char 		*heap, *w;
	char const 	*s_tmp;
	char const	*tok_s, *tok_e;
	int		tok;
	size_t		chunk;
	size_t		need;
	char		timestamp[42];
	unsigned char	bitarray[(1 << CHAR_BIT) / 8];
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return NULL;

	/* What's the largest a variable can get? */
	chunk = sizeof("deprecated") - 1;
	need = strlen(smf->smf_query_sender);
	if (need > chunk)
		chunk = need;
	need = strlen(smf->smf_query_domain);
	if (need > chunk)
		chunk = need;
	need = strlen(smf->smf_query_ip);
	if (need > chunk)
		chunk = need;
	if (flag_exp)
	{
		snprintf(timestamp, sizeof timestamp, 
			"%lu", (unsigned long)time((time_t *)0));

		need = strlen(context->sm_smtp_client_ip);
		if (need > chunk)
			chunk = need;
		need = strlen(context->sm_smtp_hostname);
		if (need > chunk)
			chunk = need;
		need = strlen(timestamp);
		if (need > chunk)
			chunk = need;
	}

	/* It might URL-quoted. */
	chunk *= 3;

	/* How much space do we need? */
	need = 1;
	s_tmp = s;
	while ((tok = sm_marid_evaluate_token(&s_tmp, e, &tok_s, &tok_e)) != 0)
	{
		switch (tok)
		{
		  case '.':
		  	need += tok_e - tok_s;
			break;

		  case '%':
		  case '_':
		  case '-':
		  	need += 3;
			break;

		  default:
		  	need += chunk;
			break;
		}
	}
	if ((w = heap = sm_marid_arena_alloc(context, need)) == NULL)
		return heap;

	s_tmp = s;
	while ((tok = sm_marid_evaluate_token(&s_tmp, e, &tok_s, &tok_e)) != 0)
	{
		char		*we;

		char const	*var_s, *var_e;
		char const	*chunk_s, *chunk_e;
		char const	*p;
		size_t		i, n;
		int		backwards;

		switch (tok)
		{
		  case '.':
		  	memcpy(w, tok_s, tok_e - tok_s);
			w += tok_e - tok_s;
			continue;

		  case '%':
		  	*w++ = '%';
			continue;

		  case '_':
		  	*w++ = ' ';
			continue;

		  case '-':
		  	*w++ = '%';
		  	*w++ = '2';
		  	*w++ = '0';
			continue;

		default:
			break;
		}

		if (sm_marid_evaluate_variable_string(
			context, tok, &var_s, &var_e, timestamp))
			continue;

		p = tok_s + 3;
		n = 0;

		if (  p < tok_e
		   && isascii((unsigned char)*p)
		   && isdigit(*p))
		{
			while (isdigit(*p))
			{
				n = n * 10 + (*p - '0');
				p++;
			}
		}
		else 
			n = (size_t)-1;
		
		backwards = 1;
		if (p < tok_e && *p == 'r')
		{
			backwards = 0;
			p++;
		}

		mark_separators(bitarray, *p == '}' ? ".}" : p);
		we = heap + need;

		for (i = 0;  i < n; i++)
		{
			if (!get_chunk(&var_s, &var_e, &chunk_s, &chunk_e,
				backwards, bitarray))

				break;
			
			if (IS_SEP(bitarray, *chunk_s))
				*--we = '.';

			else if (  isascii((unsigned char)tok_s[2])
			        && isupper(tok_s[2]))
			{
				/* URL-encode */
				for (; chunk_s < chunk_e; chunk_e--)
				{
					if (isascii((unsigned char)chunk_e[-1])
					   && (  isalnum(chunk_e[-1])
					     || MARID_IS_URL_MARK(chunk_e[-1])))
					{
						*--we = chunk_e[-1];
					}
					else
					{
						char const *hex
							= "0123456789ABCDEF";

						we[-3] = '%';
						we[-2] = hex[0xF & (chunk_e[-1]
								  >> 4)];
						we[-1] = hex[0xF & chunk_e[-1]];
						we -= 3;
					}
				}
			}
			else
			{
				/* Just copy */
				memcpy(we - (chunk_e - chunk_s),
					chunk_s,
					chunk_e - chunk_s);

				we -= chunk_e - chunk_s;
			}
		}

		memmove(w, we, (heap + need) - we);
		w += (heap + need) - we;
	}
	*w = '\0';
	sm_marid_log_check(context, w < heap + need);

	return heap;
}
