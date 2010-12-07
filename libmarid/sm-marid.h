/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

#ifndef	SM_MARID_H
#define	SM_MARID_H /* Guard against multiple includes */

#ifndef lint
static char
# ifdef __GNUC__
	__attribute__((unused))
# endif
  sm_marid_h_id[] = "@(#)$Id: sm-marid.h,v 1.4 2004/08/17 00:50:54 jutta Exp $";
#endif /* !lint */

/* system includes */
#include <stdlib.h>	/* size_t */

typedef enum {
	/* Loglevels (line up with slog levels) */

	SM_MARID_LOG_WARN 	= 3,
	SM_MARID_LOG_FAIL	= 5,
	SM_MARID_LOG_INFO	= 6,
	SM_MARID_LOG_DETAIL	= 7,
	SM_MARID_LOG_DEBUG	= 8

} sm_marid_loglevel;

/*
**  SM_MARID -- the handle structure, opaque to the application.
**	Allocate one per request, using sm_marid_new().
*/

typedef struct sm_marid sm_marid;

/*
**  SM_MARID_RESULT_TYPE -- the final outcome of a request.
**	See the draft for detailed meanings.
*/

#define SM_MARID_NEUTRAL	'?'
#define SM_MARID_PASS 		'+'
#define SM_MARID_FAIL		'-'
#define SM_MARID_SOFT_FAIL	'~'
#define SM_MARID_NONE		'0'
#define SM_MARID_TEMP_ERROR 	'4'
#define SM_MARID_PERM_ERROR 	'5'

/*
**  SM_MARID_REASON_TYPE -- details about a failure; only
**	valid if the result is SM_MARID_FAIL.  See the
**	draft for detailed meanings.
*/

typedef enum {

	SM_MARID_REASON_NONE,

	/* there was a rule against it */
	SM_MARID_NOT_PERMITTED,

	/* domain parameter is not a FQN */
	SM_MARID_MALFORMED_DOMAIN,

	/* NXDOMAIN DNS error */
	SM_MARID_DOMAIN_DOES_NOT_EXIST

} sm_marid_reason;

/*
**  SM_MARID_NEW -- initialize a check-host context.
**
**	For each ongoing check-host call, there must be an sm_marid
**	context that has been initialized with this constructor function
**	and remains valid until a result is returend.
**
**		"You can't destroy the Earth, that's where
**		I keep all my stuff!"
**						-- The Tick
**
**	(Multiple check_host()s can, and will in practice, go on at
**	the same time, but each needs their own ms_marid structure.)
**
**	Parameters:
**		app_data -- application-controlled opaque pointer passed to
**			deliver_result and dns_query.
**		app_log -- callback used to log, or NULL
**		app_alloc -- callback used to log, or NULL
**		app_log -- callback used to log, or NULL
**
**	Returns:
**		a new check_host structure.
*/

sm_marid * sm_marid_new(
	void const   *app_data,
	void	    (*app_log)(void *app_data, int level, char const *string),
	void *	    (*app_alloc)(void *app_data, size_t size),
	void	    (*app_free)(void *app_data, void *ptr));

/*
**  SM_MARID_DESTROY -- free a check-host context.
**
**	Parameters:
**		context -- structure allocated with sm_marid_new().
**
**	Returns:
**		none
*/

void sm_marid_destroy(sm_marid *_context);

/*
**  SM_MARID_CHECK_HOST -- initiate a check_host().
**
**	The final outcome of the processing is reported
**	once the application calls sm_marid_check_host_result();
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**		ip -- pointer to IP address to check
**		domain -- DNS publisher to query
**		sender -- full sending mailbox address to check
**
**	Returns:
**		Returns 0 for a success unless parameters are NULL.
*/

int sm_marid_check_host(
	sm_marid	*_context,
	char const	*_ip,
	char const	*_domain,
	char const	*_sender);

/*
**  SM_MARID_REQUEST -- get next request from marid
**
**	The sm_marid context is a factory for DNS requests.
**	It's the application's job to pull out DNS requests and
**	answer them.  Only once there are no more DNS requests,
**	the sm_marid has produced a reply to the initial check_host().
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**		type_out -- type of the DNS request to be executed.
**
**	Returns:
**		NULL if marid is done and hte application should
**		call sm_marid_check_host_result(), otherwise a
**		domain name that marid wants to know more about.
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
**			as with ADDR. Used for "exists".  
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

#define	SM_MARID_TXT 	 1
#define	SM_MARID_ADDR 	 2
#define	SM_MARID_MX	 4
#define	SM_MARID_A	 8
#define	SM_MARID_PTR	16
#define	SM_MARID_MARID	32

char const *
sm_marid_request(sm_marid *_context, int *_type);

/*
**  SM_MARID_REQUEST_RESULT -- deliver request reply to marid
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**		err -- 0 or DNS error
**		results -- vector of result strings
**		results_n -- # of elements in that vector
**
**	Returns:
**		0 if it's done, otherwise the type of DNS query MARID
**		needs answered.
**
**  	DNS errors:
**
**		The errors below are passed from the application to
**		the marid library as part of reporting on the outcome
**		of a DNS request.
**
**		Marid really just distinguishes three kinds of
**		outcomes: no error, NXDOMAIN, and everything else.
**
**		Do your own logging about DNS outcomes; this is
**		obviously not detailed enough.
*/

#define	SM_MARID_OK		0
#define	SM_MARID_ERR_NXDOMAIN	3
#define	SM_MARID_ERR_MISC	2

int sm_marid_request_result(
	sm_marid		*_context,
	int			_err,
	char const * const 	*_results,
	size_t			results_n);

/*
**  SM_MARID_CHECK_HOST_RESULT -- get final result of a "check-host" query.
**
**	Call this function as soon as sm_marid_dns_request()
**	returns 0 to receive the final result of a marid evaluation.
**
**	Parameters:
**		context -- context initialized with sm_marid_new()
**		reason_out -- optional: reason for failure 	
**		explanation_out -- optional: "explanation" string
**
**	Returns:
**		the result of the marid request.
*/

int sm_marid_check_host_result(
	sm_marid	*_context,
	int		*_reason_out,
	char const	**_explanation_buf);


/*
**  SM_MARID_IS_MARID -- utility: are we interested
**	in this record?
**
**	Call this function while answering a DNS request
**	for SM_MARID_MARID to determine whether to 
**	ignore or use a RR or TXT record.
**
**	Parameters:
**		context -- the sm_marid context for the query
**		s -- beginning of the text chunk
**		n -- # of bytes pointed to by s
**
**	Returns:
**		0 if this is a text record for something else,
**		1 if it's a text record suitable for use with
**			a response to a query of type SM_MARID_MARID.
*/

int sm_marid_dns_is_marid(sm_marid *context, char const *s, size_t n);

/*
**  SM_MARID_SET_MAX_DEPTH -- set maximum recursion depth
**
**	Parameters:
**		context -- handle for which to set this
**		max -- maximum recursion depth (0: unlimited)
**
**	Returns:
**		old value of recursion depth
*/

size_t sm_marid_set_max_depth(sm_marid *_context, size_t _max);

/*
**  SM_MARID_SET_MAX_REQUESTS -- set maximum # of requests
**
**	Parameters:
**		context -- handle for which to set this
**		max -- maximum number of requests (0: unlimited)
** 
**	Returns:
**		old value of maximum request count
*/

size_t sm_marid_set_max_requests(sm_marid *_context, size_t _max);

/*
**  SM_MARID_SET_VERSION_PATTERNS -- set which version strings are required
**
**	In the pattern string,
**	     sequence 		stands for 
**		%%		a literal %
**		%d		1 or more digits
**		%v		0 or more VCHAR (%x21-%x7F)
**		%,		end-of-token-and-stop, or comma-and-continue
**
**	Parameters:
**		marid -- context
**		patvec -- (static const) argv-style vector of
**			version patterns, NULL-terminated.
**
**	Returns:
**		old value of version pattern vector
*/

char const * const * sm_marid_set_version_patterns(
	sm_marid 		*_context,
	char const * const 	*_patterns);

/*
**  SM_MARID_VERSION_PATTERNS_** -- good values to pass to
**	sm_marid_set_version_patterns():
*/

extern char const
* const sm_marid_version_patterns_00[], 	/* v=spf1 */
* const	sm_marid_version_patterns_01[], 	/* spf2.%d/pra%,%v */
* const	sm_marid_version_patterns_any[];	/* any of the above */

#endif /* SM_MARID_H */
