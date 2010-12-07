/*
**  Copyright (c) 2004, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

/* system includes */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* libmarid includes */
#include "sm-maridp.h"

#ifndef lint
static char sm_marid_unused
sm_marid_c_id[] = "@(#)$Id: sm-marid.c,v 1.7 2008/05/15 18:37:24 msk Exp $";
#endif /* !lint */

char const * const
sm_marid_version_patterns_00[] = { "v=spf1",		NULL };
char const * const
sm_marid_version_patterns_01[] = { "spf2.%d/pra%,%v", 	NULL };
char const * const
sm_marid_version_patterns_02[] = { "spf2.%d/mfrom%,%v", NULL };
char const * const
sm_marid_version_patterns_any[] = { "v=spf1", "spf2.%d/pra%,%v", "spf2.%d/mfrom%,%v", NULL };

/*
**  MARID_DEFAULT_FREE -- default free callback if application passes NULL. 
**
**	Parameters:
**		data -- application data; ignored
**		ptr -- pointer to free
**
**	Returns:
**		none
*/

static void 
marid_default_free(void  *data, void *mem)
{
	(void)data;
	return free(mem);
}

/*
**  MARID_DEFAULT_ALLOC -- default alloc callback if application passes NULL. 
**
**	Parameters:
**		data -- application data; ignored
**		size -- # of bytes to allocate
**
**	Returns:
**		NULL on allocation error, otherwise the allocated storage.
*/

static void *
marid_default_alloc(void *data, size_t	size)
{
	(void)data;
	return malloc(size);
}

/*
**  MARID_DEFAULT_LOG -- default log callback if application passes NULL. 
**
**	Parameters:
**		data -- application data.  Interpreted as starting
**			with an integer loglevel, if non-NULL.
**		level -- level of the logmessage
**		text -- text to log, without trailing \n.
**
**	Returns:
**		none
*/

static void 
marid_default_log(
	void 		*data,
	int   		level,
	char const	*text)
{
	int		default_level = SM_MARID_LOG_WARN;

	if (data == NULL)
		data = &default_level;
	if (data != NULL && level > *(int *)data)
	   	return;
	fprintf(stderr, "marid: %s\n", text);
}

/*
**  SM_MARID_NEW -- initialize a marid context.
**
**	For each ongoing check-host call, there must be an sm_marid
**	context that has been initialized with this constructor function
**	and remains valid until a result is returend.
**
**	(Multiple check_host()s can, and will in practice, go on at
**	the same time, but each needs their own ms_marid structure.)
**
**	Parameters:
**		app_data -- application-controlled opaque pointer for callbacks
**		app_log -- callback used to log, or NULL
**		app_alloc -- callback used to allocate memory, or NULL
**		app_free -- callback used to free memory, or NULL
**
**	Returns:
**		a new check_host structure.
*/

sm_marid *
sm_marid_new(
	void const  		*app_data,
	void			(*app_log)(void *, int, char const *),
	void			*(*app_alloc)(void *, size_t),
	void			(*app_free)(void *, void *))
{
	sm_marid		tmp;
	sm_marid  		*mar;

	memset(&tmp, 0, sizeof tmp);

	SM_MARID_CONTEXT_SET(&tmp);
	tmp.sm_app_data  = (void *)app_data; 

	tmp.sm_app_alloc= (app_alloc == NULL ? marid_default_alloc : app_alloc);
	tmp.sm_app_free = (app_free  == NULL ? marid_default_free  : app_free );
	tmp.sm_app_log  = (app_log   == NULL ? marid_default_log   : app_log  );

	mar = sm_marid_arena_alloc(&tmp, sizeof(*mar));
	if (mar == NULL)
		return NULL;

	*mar = tmp;
	mar->sm_smtp_hostname   = "";
	mar->sm_smtp_client_ip 	= "";
	mar->sm_version_patterns = sm_marid_version_patterns_any;

	return mar;
}

/*
**  SM_MARID_SET_MAX_DEPTH -- set maximum recursion depth
**
**	Parameters:
**		marid -- context
**		depth -- maximum recursion depth
**
**	Returns:
**		old value of recursion depth
*/

size_t
sm_marid_set_max_depth(sm_marid *context, size_t max)
{
	size_t		old;


	old = context->sm_depth_max;
	context->sm_depth_max = max;

	return old;
}

/*
**  SM_MARID_SET_MAX_REQUESTS -- set maximum # of requests
**
**	Parameters:
**		marid -- context
**		num -- maximum number of requests
**
**	Returns:
**		old value of maximum request count
*/

size_t
sm_marid_set_max_requests(sm_marid *context, size_t max)
{
	size_t		old;


	old = context->sm_request_max;
	context->sm_request_max = max;

	return old;
}

/*
**  SM_MARID_SET_VERSION_PATTERNS -- set which version
**	strings are required
**
**	Parameters:
**		marid -- context
**		patvec -- (static const) argv-style vector of
**			version patterns, NULL-terminated.
**
**	Returns:
**		old value of version pattern vector
*/

char const * const *
sm_marid_set_version_patterns(sm_marid *context, char const * const *pat)
{
	char const * const 	*old;


	old = context->sm_version_patterns;
	context->sm_version_patterns = pat;

	return old;
}

/*
**  SM_MARID_DESTROY -- free resources associated with a call.
**
**	After the call, the context pointer is invalid.
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**
**	Returns:
**		none.
*/

void
sm_marid_destroy(sm_marid *context)
{
	if (!SM_MARID_CONTEXT_CHECK(context))
		return;

	context->sm_magic[0] = 0;
 	sm_marid_arena_destroy(
		context->sm_arena,
		context->sm_app_data,
		context->sm_app_free);
}

/*
**  SM_MARID_CHECK_HOST_DELIVER_RESULT_CALLBACK -- check_host() result handler
**
**	This callback is called to deliver the result of the outermost
**	check-host call to the caller.
**
**	Since our caller is the application, we just store the
**	result in the handle.  The application will later call
**	sm_marid_check_host_result() to get these values.
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**		prev -- returning context (no longer on stack)
**
**	Returns:
**		none
*/

static void
sm_marid_check_host_deliver_result_callback(
	sm_marid 		*context,
	sm_marid_frame const 	*prev)
{
	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, prev != NULL))
		return;

	context->sm_result      = prev->smf_result;
	context->sm_reason      = prev->smf_reason;
	context->sm_explanation = prev->smf_explanation;
}

/*
**  SM_MARID_CHECK_HOST -- check_host() function
**
**	This initiates check_host() as described in 
**	draft-ietf-marid-protocol-00.txt, but with continuation
**	passing.
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**		ip -- pointer to IP address to check
**		domain -- DNS publisher to query
**		sender -- full sending mailbox address to check
**
**	Returns:
**		0 if a query has been successfully initiated,
**		EINVAL -- programmer error (e.g. a NULL context)
**		ENOMEM -- we're out of memory.
*/

int
sm_marid_check_host(
	sm_marid	*context,
	char const	*ip,
	char const	*domain,
	char const	*sender)
{
	sm_marid_frame 	*smf;

	if (!SM_MARID_CONTEXT_CHECK(context))
		return EINVAL;	
	
	sm_marid_log(context, SM_MARID_LOG_INFO,
		"check_host ip=%s domain=%s sender=%s",
		ip 	!= NULL? ip     : "(null)",
		domain 	!= NULL? domain : "(null)",
		sender 	!= NULL? sender : "(null)");

	smf = sm_marid_check_host_frame(context, ip, domain, sender,
		sm_marid_check_host_deliver_result_callback);
	if (smf == NULL)
		return ENOMEM;

	return sm_marid_check_host_run(context);
}

/*
**  SM_MARID_CHECK_HOST_RESULT -- get final result of a "check-host" query.
**
**	Used by the application to receive the final result of
**	a marid evaluation.
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**		reason_out -- optional: reason for failure 	
**		explanation_out -- optional: "explanation" string
**
**	Returns:
**		0 on error, the result of the marid request otherwise.
*/

static char const *
check_host_result_name(int result)
{
	switch (result)
	{
	  default:
	  	break;
	  case SM_MARID_NEUTRAL:
	  	return "Neutral";
	  case SM_MARID_PASS:
	  	return "Pass";
	  case SM_MARID_FAIL:	
	  	return "Fail";
	  case SM_MARID_SOFT_FAIL:	
	  	return "SoftFail";
	  case SM_MARID_NONE:
	  	return "None";
	  case SM_MARID_TEMP_ERROR:	
	  	return "TempError";
	  case SM_MARID_PERM_ERROR:	
	  	return "PermError";
	}
	return "unexpected result";
}

static char const *
check_host_reason_name(int reason)
{
	switch (reason)
	{
	  case SM_MARID_NOT_PERMITTED:
		return "NotPermitted";
	  case SM_MARID_MALFORMED_DOMAIN:
		return "MalformedDomain";
	  case SM_MARID_DOMAIN_DOES_NOT_EXIST:
		return "DomainDoesNotExist";
	  default:
		break;
	}
	return "unexpected reason";
}

/*
**  SM_MARID_CHECK_HOST_LOG_RESULT -- log check_host() result
**
**	This initiates check_host() as described in 
**	draft-ietf-marid-protocol-00.txt, but with continuation
**	passing.
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**		ip -- pointer to IP address to check
**		domain -- DNS publisher to query
**		sender -- full sending mailbox address to check
**
**	Returns:
**		0 if a query has been successfully initiated,
**		EINVAL -- programmer error (e.g. a NULL context)
**		ENOMEM -- we're out of memory.
*/

void
sm_marid_check_host_log_result(sm_marid *context)
{
	sm_marid_frame 	*smf;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context, (smf = context->sm_frame) != NULL))
		return;	
	
	sm_marid_log(context, SM_MARID_LOG_DEBUG,
		"%*s<<< check_host ip=%s domain=%s sender=%s: %s%s%s%s%s",
		smf->smf_depth * 3, "", 
		smf->smf_query_ip != NULL? smf->smf_query_ip : "(null)",
		smf->smf_query_domain != NULL? smf->smf_query_domain : "(null)",
		smf->smf_query_sender != NULL? smf->smf_query_sender : "(null)",
		check_host_result_name(smf->smf_result),
		smf->smf_reason == 0 ? "" : " ", 
		smf->smf_reason == 0 ? "" :
			check_host_reason_name(smf->smf_reason),
		smf->smf_explanation == NULL ? "" : " ",
		smf->smf_explanation == NULL ? "" : smf->smf_explanation);
}

int
sm_marid_check_host_result(
	sm_marid	*context,
	int		*reason_out,
	char const	**explanation_out)
{
	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || context->sm_frame != NULL)
		return 0;

	if (explanation_out != NULL)
		*explanation_out = context->sm_explanation;
	if (reason_out != NULL)
		*reason_out = context->sm_reason;

	sm_marid_log(context, SM_MARID_LOG_INFO,
		"check_host: %s%s%s",
		check_host_result_name(context->sm_result),
		context->sm_reason == 0 ? "" : " ", 
		context->sm_reason == 0 ? "" :
			check_host_reason_name(context->sm_reason),
		context->sm_explanation == NULL ? "" : " ",
		context->sm_explanation == NULL ? "" : context->sm_explanation);

	return context->sm_result;
}

/*
**  SM_MARID_REQUEST -- get next request from marid
**
**	The sm_marid context is a factory for requests, mostly
**	DNS requests or macro-requests composed of DNS requests.
**	It's the application's job to pull out requests and
**	answer them.  Only once there are no more requests,
**	the sm_marid has produced a reply to the initial check_host().
**
**	Parameters:
**		context -- context initialized with sm_marid_check_host_new()
**		type_out -- type of the DNS request to be executed.
**
**	Returns:
**		NULL if marid is done and the application should
**		call sm_marid_check_host_result(),
**		otherwise a domain name that marid wants to know more about.
**
**	Request types:
**
**  		SM_MARID_TXT -- look up TXT records.
**			(Used for "exp" modifier.)
**
**  		SM_MARID_ADDR -- both A and AAAA records for the domain
**			(if available), with returned IP address as text
**			(e.g., "127.0.0.1")
**
**  		SM_MARID_MX -- perform an MX lookup on the <target-name>,
**			then perform an A lookup on each MX name returned,
**			in order of MX priority; return the results
**			as with the "ADDR" format.
**
**			Note Regarding Implicit MXes: If the <target-name>
**			has no MX records, the call MUST NOT pretend the
**			target is its single MX, and MUST NOT default to
**			an A lookup on the <target-name> directly.
**			This behavior breaks with the legacy "implicit MX"
**			rule. 
**
**  		SM_MARID_A -- perform an A lookup; return results
**			as with DNS_ADDR. Used for "exists".  
**
**  		SM_MARID_PTR -- perform a verified ptr query,
**			used for "ptr":
**	   		Perform a PTR lookup against the argument.
**	   		For each record returned, validate the host name by
**	   			looking up its IP address.
**  
**		  	In pseudocode:
**
** 	    		sending-host_names := ptr_lookup(sending-host_IP);
**	    		for each name in (sending-host_names) {
**			       IP_addresses := a_lookup(name);
**	      		     if the sending-host_IP is one of the IP_addresses {
**	         		validated_sending-host_names += name;
**     	    		}   }
**
**  		SM_MARID_MARID -- look up SPF records
**
**			Look up TXT and MARID RR records for the domain.
**			Ignore those for which
**			sm_marid_check_host_dns_is_marid() returns false.
**
**			If you hit more than one record of any one type
**			(TXT or RR), those two records are the result.
**			(Having more than one record of the same 
**			type is an error condition.)
**
**			If there's a RR, return the RR.
**			Otherwise, return the TXT record (or no records).
*/

static char const *
sm_marid_request_type_name(int type)
{
	switch (type)
	{
	  case SM_MARID_TXT:
	  	return "txt";
	  case SM_MARID_ADDR:
	  	return "addr";
	  case SM_MARID_MX:
	  	return "mx";
	  case SM_MARID_A:
	  	return "a";
	  case SM_MARID_PTR:
	  	return "ptr";
	  case SM_MARID_MARID:
	  	return "marid";
	}
	return "unexpected type";
}

char const *
sm_marid_request(sm_marid *context, int	*type)
{
	char const	*domain;

	if (!SM_MARID_CONTEXT_CHECK(context))
		return NULL;

	if ((domain = context->sm_dns_domain) == NULL)
	{
		*type = 0;
		sm_marid_log(context, SM_MARID_LOG_DEBUG,
			"%*s  < no more requests",
			  context->sm_frame == NULL ? 0  
			: context->sm_frame->smf_depth * 3, "");
	}
	else
	{
		*type = context->sm_dns_type;

		context->sm_dns_domain = NULL;
		context->sm_dns_type   = 0;

		sm_marid_log(context, SM_MARID_LOG_DEBUG, "%*s  < %s %s?",
			  context->sm_frame == NULL ? 0  
			: context->sm_frame->smf_depth * 3, "",
			sm_marid_request_type_name(*type),
			domain);
	}

	return domain;
}

/*
**  SM_MARID_REQUEST_RESULT -- deliver result of an DNS query
**
**	This function is called by the application to pass the
**	result of a query to the marid library, and to resume
**	execution of a check-host request.
**
**	The result record must have the correct class and the
**	correct domain name; it's up to the application to ensure
**	that they match.
**
**	Parameters:
**		context -- the sm_marid context for the whole query
**		domain -- domain we looked up
**		err -- the result of the DNS callback as an error number
**		records -- if there was a response, this is it. 
**
**	Returns:
**		0 on success, -1 on programming error.
*/

int
sm_marid_request_result(
	sm_marid			*context,
	int				err,
	char const * const 		*vec,
	size_t				vec_n)
{
	sm_marid_dns_result_callback	*callback;
	int				indent;

	if (  !SM_MARID_CONTEXT_CHECK(context)
	   || !sm_marid_log_check(context,
	   	(callback = context->sm_dns_result) != NULL))
		return EINVAL;

	indent = context->sm_frame == NULL
		? 0 : context->sm_frame->smf_depth * 3;

	if (err != SM_MARID_OK) 
		sm_marid_log(context, SM_MARID_LOG_DEBUG, "%*s  > %s",
			indent, "", 
			err == SM_MARID_ERR_NXDOMAIN ? "NXDOMAIN" : "MISC ERR");
	else if (vec_n == 1)
		sm_marid_log(context, SM_MARID_LOG_DEBUG, "%*s  > %s",
			indent, "", vec[0]);
	else
		sm_marid_log(context, SM_MARID_LOG_DEBUG, "%*s  > %lu records",
			indent, "", (unsigned long)vec_n);

	context->sm_dns_result = NULL;
	(* callback)(context, err, vec, vec_n);

	return 0;
}
