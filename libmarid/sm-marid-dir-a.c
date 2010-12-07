/*
**  Copyright (c) 2004, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_dir_a_c_id[] = "@(#)$Id: sm-marid-dir-a.c,v 1.6 2008/05/15 18:37:24 msk Exp $";
#endif /* !lint */

/*
**  SM_MARID_DIR_A_DNS_RESULT -- handle result of DNS query for "a" directive.
**
**	Parameters:
**		context -- calling context
**		err -- DNS lookup error or 0
**		vec -- results
**		vec_n -- # of results
**
**	Returns:
**		none
*/

static void
sm_marid_dir_a_dns_result(
	sm_marid 		*context,
	int 			err,
	char const * const 	*vec,
	size_t			vec_n)
{
	sm_marid_frame		*smf;
	size_t			i;
	unsigned char		canon_ip[128 / 8];
	size_t			canon_ip_n;

	smf = context->sm_frame;

	canon_ip_n = sizeof(canon_ip);
	if (sm_marid_ip_canon(
		smf->smf_query_ip,
		smf->smf_query_ip + strlen(smf->smf_query_ip),
		canon_ip, &canon_ip_n))
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** syntax error in IP address \"%s\" ***",
			smf->smf_query_ip);

		smf->smf_result = SM_MARID_PERM_ERROR;
		sm_marid_check_host_deliver_result(context);
		return;
	}

	if (err == 0)
		for (i = 0; i < vec_n; i++)
		{
			unsigned char		canon_rec[128 / 8];
			size_t			canon_rec_n;

			canon_rec_n = sizeof(canon_rec);
			if (sm_marid_ip_canon(vec[i], vec[i] + strlen(vec[i]),
				canon_rec, &canon_rec_n))
			{
				sm_marid_log(context, SM_MARID_LOG_FAIL,
					"*** syntax error in IP "
					"address \"%s\" ***", vec[i]);

				smf->smf_result = SM_MARID_PERM_ERROR;
				sm_marid_check_host_deliver_result(context);
				return;
			}
			if (canon_ip_n != canon_rec_n)
				continue;

			if (sm_marid_ip_eq(
				canon_ip, canon_rec, canon_ip_n,
				canon_ip_n == 4 ?  smf->smf_cidr_ip4
						:  smf->smf_cidr_ip6))
			{
				smf->smf_result = smf->smf_prefix;
				if (smf->smf_result == SM_MARID_FAIL)
					smf->smf_reason
						= SM_MARID_NOT_PERMITTED;
				sm_marid_check_host_deliver_result(context);
				return;
			}
		}

	sm_marid_check_host_record_continue(context);
}

/*
**  SM_MARID_DIR_A -- handle an "a" directive
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_dir_a(sm_marid *context, sm_marid_expression const *expr)
{
	char const	*tmp;
	char const	*s, *e;
	sm_marid_frame	*smf;

	smf = context->sm_frame;

	/* Scan trailing cidr length(s) */
	if (  (s = expr->smx_cidr_s) != NULL
	   && (e = expr->smx_cidr_e) != NULL)
	{
		sm_marid_scan_cidr(s, &e, &smf->smf_cidr_ip4,
					  &smf->smf_cidr_ip6);
	}
	else
	{
		smf->smf_cidr_ip4 = 32;
		smf->smf_cidr_ip6 = 128;
	}

	s = expr->smx_value_s;
	e = expr->smx_value_e;

	/* Expand the value of the right-hand side */
	tmp = sm_marid_domain_spec(context, s, e);
	if (tmp == NULL)
	{
		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);
	}
	else
	{
		/* remember the prefix. */
		smf->smf_prefix = expr->smx_prefix;

		/* Perform a DNS A or AAAA query on that string. */
		sm_marid_check_host_dns_query(context,
			SM_MARID_ADDR, tmp, sm_marid_dir_a_dns_result);
	}
	return 1;
}

/*
**  SM_MARID_DIR_MX -- handle an "mx" directive
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_dir_mx(sm_marid *context, sm_marid_expression const *expr)
{
	sm_marid_frame	*smf;
	char const	*tmp;
	char const	*s, *e;

	smf = context->sm_frame;

	/* Scan trailing cidr length(s) */
	if (  (s = expr->smx_cidr_s) != NULL
	   && (e = expr->smx_cidr_e) != NULL)
	{
		sm_marid_scan_cidr(s, &e,
			&smf->smf_cidr_ip4,
			&smf->smf_cidr_ip6);
	}
	else
	{
		smf->smf_cidr_ip4 = 32;
		smf->smf_cidr_ip6 = 128;
	}

	s = expr->smx_value_s;
	e = expr->smx_value_e;

	/* Expand the value of the right-hand side */
	tmp = sm_marid_domain_spec(context, s, e);
	if (tmp == NULL)
	{
		smf->smf_result = SM_MARID_TEMP_ERROR;
		sm_marid_check_host_deliver_result(context);
	}
	else
	{
		/* remember the prefix. */
		smf->smf_prefix = expr->smx_prefix;

		/* Perform a recursive DNS MX query on that string. */
		sm_marid_check_host_dns_query(context,
			SM_MARID_MX, tmp, sm_marid_dir_a_dns_result);
	}
	return 1;
}
