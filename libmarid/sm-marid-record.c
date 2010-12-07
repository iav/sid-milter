/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <ctype.h>
#include <stdio.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_record_c_id[] = "@(#)$Id: sm-marid-record.c,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

typedef struct
{
	sm_marid_expression_type	smm_type;
	char const			*smm_name;
	int				(* smm_execute)(
						sm_marid *,
						sm_marid_expression const *);
} sm_marid_map;

static const sm_marid_map sm_marid_op[] =
{
  { SM_MARID_MODIFIER,	"redirect", 	sm_marid_mod_redirect  },
  { SM_MARID_MODIFIER, 	"exp", 		sm_marid_mod_exp	},
  { SM_MARID_MODIFIER, 	"default", 	sm_marid_mod_ignore	},
  { SM_MARID_MODIFIER, 	"accredit", 	sm_marid_mod_ignore	},
  { SM_MARID_MODIFIER, 	"match_subdomains",  sm_marid_mod_ignore },

  { SM_MARID_DIRECTIVE,	"all", 		sm_marid_dir_all	},
  { SM_MARID_DIRECTIVE,	"include", 	sm_marid_dir_include	},
  { SM_MARID_DIRECTIVE,	"a", 		sm_marid_dir_a		},
  { SM_MARID_DIRECTIVE,	"mx", 		sm_marid_dir_mx		},
  { SM_MARID_DIRECTIVE,	"ptr", 		sm_marid_dir_ptr	},
  { SM_MARID_DIRECTIVE,	"ip4", 		sm_marid_dir_ip4	},
  { SM_MARID_DIRECTIVE,	"ip6", 		sm_marid_dir_ip6	},
  { SM_MARID_DIRECTIVE,	"exists", 	sm_marid_dir_exists	},

  /* Sentinel */
  { 0 }
};

/*
**  SM_MARID_CHECK_HOST_RECORD_MODIFIERS -- execute trailing modifiers.
**
**	Scan the remaining text of a record, evaluating modifiers,
**	but skipping directives.
**
**	Unlike its sibling sm_marid_check_host_record_continue(),
**	this call doesn't normally go off into continuation-passing;
**	it just calls the modifiers.
**
**	Parameters:
**		context -- the sm_marid context for the whole query
**
**	Returns:
**		0 normally,
**		nonzero if a syntax error was executed and the caller
**		should to return immediately because a result has 
**		already been delivered.
*/

int
sm_marid_check_host_record_modifiers(sm_marid *context)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return 0;

	if (  smf->smf_record_s == NULL
	   || smf->smf_record_e == NULL)
	   	return 0;

	/* skip leading spaces */
	while (  smf->smf_record_s < smf->smf_record_e
	      && *smf->smf_record_s == ' ')
		smf->smf_record_s++;

	while (smf->smf_record_s < smf->smf_record_e)
	{
		sm_marid_map const	*m;
		sm_marid_expression	x;
		char const		*xs, *xe;

		xs = smf->smf_record_s;
		xe = smf->smf_record_e;

		if (sm_marid_scan_expression(
			&smf->smf_record_s, smf->smf_record_e, &x))
		{
			sm_marid_log(context, SM_MARID_LOG_FAIL,
				"*** syntax error while scanning "
				"for modifiers in \"%.*s\" ***",
				xe - xs, xs);

			smf->smf_result = SM_MARID_PERM_ERROR;
			sm_marid_check_host_deliver_result(context);

			return 1;
		}

		/* At this point, we don't care about anything but modifiers. */
		if (x.smx_type != SM_MARID_MODIFIER)
			continue;

		for (m = sm_marid_op; m->smm_name != NULL; m++)

			if (  m->smm_type == SM_MARID_MODIFIER
			   && tolower(*m->smm_name) == tolower(*x.smx_name_s)
			   && sm_marid_memstrcaseeq(
			   	x.smx_name_s, x.smx_name_e, m->smm_name))
					break;

		if (m->smm_name != NULL)
			if ((* m->smm_execute)(context, &x))
				return 1;
	}
	return 0;
}


/*
**  SM_MARID_CHECK_HOST_RECORD_CONTINUE -- execute a query against a record.
**
**	We've dispensed with the initial lookup and have checked
**	the record's version.  Execute the remainder of the record
**	against the query parameters stored in the context.
**
**	Parameters:
**		context -- the sm_marid context for the whole query
**
**	Returns:
**		none.
*/

void
sm_marid_check_host_record_continue(sm_marid *context)
{
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;

	if (  smf->smf_record_s == NULL
	   || smf->smf_record_e == NULL)
	{
		sm_marid_mod_redirect_execute(context);
	   	return;
	}

	/* skip leading spaces */
	while (  smf->smf_record_s < smf->smf_record_e
	      && *smf->smf_record_s == ' ')
		smf->smf_record_s++;

	while (smf->smf_record_s < smf->smf_record_e)
	{
		sm_marid_map const	*m;
		sm_marid_expression	x;
		char const		*xs, *xe;

		xs = smf->smf_record_s;
		xe = smf->smf_record_e;

		if (sm_marid_scan_expression(
			&smf->smf_record_s, smf->smf_record_e, &x))
		{
			sm_marid_log(context, SM_MARID_LOG_FAIL,
				"*** syntax error while scanning \"%.*s\" ***",
				xe - xs, xs);

			smf->smf_result = SM_MARID_PERM_ERROR;
			sm_marid_check_host_deliver_result(context);

			return;
		}

		for (m = sm_marid_op; m->smm_name != NULL; m++)

			if (  m->smm_type == x.smx_type
			   && tolower(*m->smm_name) == tolower(*x.smx_name_s)
			   && sm_marid_memstrcaseeq(
			   	x.smx_name_s, x.smx_name_e, m->smm_name))
					break;

		if (m->smm_name != NULL)
		{
			if ((* m->smm_execute)(context, &x))
			   	return;
		}
		else
		{
			/*
			**  Unrecognized mechanisms cause processing to abort:
			**  If, during evaluation of a record, check_host()
			**  encounters a mechanism which it does not
			**  understand, then it terminates processing and
			**  returns "PermError", without evaluating any
			**  further mechanisms.  Mechanisms listed before
			**  the unknown mechanism MUST, however, be evaluated.
			*/

			if (x.smx_type == SM_MARID_DIRECTIVE)
			{
				sm_marid_log(context, SM_MARID_LOG_FAIL,
					"*** unrecognized directive \"%.*s\" "
					"***", x.smx_name_e - x.smx_name_s,
					x.smx_name_s);

				smf->smf_result = SM_MARID_PERM_ERROR;
				sm_marid_check_host_deliver_result(context);
				return;
			}
		}
	}
	sm_marid_mod_redirect_execute(context);
}
