/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <string.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_arena_c_id[] = "@(#)$Id: sm-marid-arena.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

struct sm_marid_arena
{
	struct sm_marid_arena	*sma_next;
	void			*sma_data;
};

void *
sm_marid_arena_alloc(sm_marid *context, size_t size)
{
	sm_marid_arena 	*tmp;

	if (size == 0)
		size++;

	tmp = (* context->sm_app_alloc)(context->sm_app_data, sizeof(*tmp));
	if (tmp == NULL)
		return NULL;
	
	tmp->sma_data = (* context->sm_app_alloc)(context->sm_app_data, size);
	if (tmp->sma_data == NULL)
	{
		(* context->sm_app_free)(context->sm_app_data, tmp);
		return NULL;
	}

	tmp->sma_next = context->sm_arena;
	context->sm_arena = tmp;

	return tmp->sma_data;
}

void *
sm_marid_arena_memdup(sm_marid *context, char const *s, char const *e)
{
	char  	*tmp;

	tmp = sm_marid_arena_alloc(context, 1 + (e - s));
	if (tmp == NULL)
		return NULL;
	memcpy(tmp, s, e - s);
	tmp[e - s] = '\0';

	return tmp;
}

void
sm_marid_arena_destroy(
	sm_marid_arena 	*a,
	void		*app_data,
	void		(*app_free)(void *, void *))
{
	sm_marid_arena 	*tmp;

	while (a != NULL)
	{
		tmp = a;
		a = a->sma_next;

		(* app_free)(app_data, tmp->sma_data);
		(* app_free)(app_data, tmp);
	}
}
