/*
**  Copyright (c) 2004, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <stdarg.h>
#include <stdio.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_log_c_id[] = "@(#)$Id: sm-marid-log.c,v 1.4 2008/05/15 18:37:19 msk Exp $";
#endif /* !lint */

void
sm_marid_log(sm_marid *context, sm_marid_loglevel level, const char *fmt, ...)
{
	va_list va;
	char 	buf[1024];

	if (context == NULL || fmt == NULL)
		return;

	va_start(va, fmt);
	vsnprintf(buf, sizeof buf, fmt, va);
	va_end(va);

	(*context->sm_app_log)(context->sm_app_data, level, buf);
}
