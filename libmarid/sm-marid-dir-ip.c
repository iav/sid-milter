/*
**  Copyright (c) 2004, 2006 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_dir_ip_c_id[] = "@(#)$Id: sm-marid-dir-ip.c,v 1.5 2006/05/22 22:06:16 msk Exp $";
#endif /* !lint */

/*
**  SM_MARID_DIR_IP4 -- handle an "ip4" directive
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_dir_ip4(sm_marid *context, sm_marid_expression const *expr)
{
	char const		*s, *e;
	unsigned char		ip4[4];
	size_t			ip4_n;
	unsigned char		qry[4];
	size_t			qry_n;
	sm_marid_frame		*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return 1;

	ip4_n = sizeof(ip4);
	qry_n = sizeof(qry);

	s = expr->smx_value_s;
	e = expr->smx_value_e;
	if (s == NULL || e == NULL)
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** ip4: missing IP address ***");

		smf->smf_result = SM_MARID_PERM_ERROR;
		sm_marid_check_host_deliver_result(context);
		return 1;
	}

	if (sm_marid_scan_cidr(s, &e, &smf->smf_cidr_ip4, NULL)
	   || sm_marid_ip_canon(s, e, ip4, &ip4_n))
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** ip4: syntax error in IP address \"%.*s\" ***",
			e - s, s);

		smf->smf_result = SM_MARID_PERM_ERROR;
		sm_marid_check_host_deliver_result(context);
		return 1;
	}
	if (sm_marid_ip_canon(smf->smf_query_ip,
		smf->smf_query_ip + strlen(smf->smf_query_ip),
		qry, &qry_n))
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** ip4: syntax error in IP address \"%s\" ***",
			smf->smf_query_ip);

		smf->smf_result = SM_MARID_PERM_ERROR;
		sm_marid_check_host_deliver_result(context);
		return 1;
	}

	if (  qry_n == ip4_n
	   && sm_marid_ip_eq(qry, ip4, qry_n, smf->smf_cidr_ip4))
	{
		smf->smf_result = expr->smx_prefix;
		if (smf->smf_result == SM_MARID_FAIL)
			smf->smf_reason = SM_MARID_NOT_PERMITTED;
		sm_marid_check_host_deliver_result(context);
		return 1;
	}
	return 0;
}

/*
**  SM_MARID_DIR_IP6 -- handle an "ip6" directive
**
**	Parameters:
**		context -- calling context
**		expr -- pre-parsed expression
**
**	Returns:
**		none
*/

int
sm_marid_dir_ip6(sm_marid *context, sm_marid_expression const *expr)
{
	char const		*s, *e;
	unsigned char		ip6[128 / 8];
	size_t			ip6_n;
	unsigned char		qry[128 / 8];
	size_t			qry_n;
	sm_marid_frame	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return 1;
	
	ip6_n = sizeof(ip6);
	qry_n = sizeof(qry);

	if (  (s = expr->smx_value_s) == NULL
	   || (e = expr->smx_value_e) == NULL
	   || sm_marid_scan_cidr(s, &e, NULL, &smf->smf_cidr_ip6)
	   || sm_marid_ip_canon(s, e, ip6, &ip6_n)
	   || sm_marid_ip_canon(smf->smf_query_ip,
		smf->smf_query_ip
			+ strlen(smf->smf_query_ip),
		qry, &qry_n))
	{
		sm_marid_log(context, SM_MARID_LOG_FAIL,
			"*** ip6: syntax error in IP address \"%s\" ***",
			smf->smf_query_ip);

		smf->smf_result = SM_MARID_PERM_ERROR;
		sm_marid_check_host_deliver_result(context);
		return 1;
	}

	if (  qry_n == ip6_n
	   && sm_marid_ip_eq(qry, ip6, qry_n, smf->smf_cidr_ip6))
	{
		smf->smf_result = expr->smx_prefix;
		if (smf->smf_result == SM_MARID_FAIL)
			smf->smf_reason = SM_MARID_NOT_PERMITTED;
		sm_marid_check_host_deliver_result(context);
		return 1;
	}
	return 0;
}
