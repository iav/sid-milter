/*
**  Copyright (c) 2004, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
*/

#ifndef	SM_MARIDP_H
#define	SM_MARIDP_H /* Guard against multiple includes */

#ifdef __GNUC__
# define sm_marid_unused	__attribute__((unused))
#else
# define sm_marid_unused	/* */
#endif

#ifndef lint
static char sm_marid_unused
sm_maridp_h_id[] = "@(#)$Id: sm-maridp.h,v 1.6 2008/05/15 18:37:24 msk Exp $";
#endif /* !lint */

/* system includes */
#include <stdarg.h>

/* libmarid includes */
#include "sm-marid.h"

/*
**  SM_MARID_DELIVER_RESULT -- callback that consumes the
**	result for a single frame.
*/

typedef struct sm_marid_frame 	sm_marid_frame;

typedef void sm_marid_deliver_result(
	sm_marid 		*_context,
	sm_marid_frame const 	*_result);

struct sm_marid_frame {

	size_t			smf_depth;
	struct sm_marid_frame	*smf_prev;

	sm_marid_deliver_result	*smf_deliver_result;
	void			*smf_deliver_result_data;
	
	/*
	**  SMF_QUERY_* -- these three parameters are copies of the ones 
	**  	passed into sm_marid_check_host().
	*/

	char const		*smf_query_domain;
	char const		*smf_query_ip;
	char const		*smf_query_sender;

	int			smf_result;
	int			smf_reason;
	char const		*smf_explanation;

	/* Record we're evaluating */
	char const		*smf_record_s;
	char const		*smf_record_e;

	/* Scanned CIDR length */
	size_t			smf_cidr_ip4;
	size_t			smf_cidr_ip6;

	/* Scanned prefix */
	char			smf_prefix;

	/* NULL unless there was a redirect modifier. */
	char const		*smf_redirect_s;
	char const		*smf_redirect_e;
	unsigned int		smf_redirect_tried: 1;

	/* NULL unless there was an exp modifier. */
	char const		*smf_exp_s;
	char const		*smf_exp_e;
	unsigned int		smf_exp_tried: 1;

	/* Target value from expression we're evaluating. */
	char const		*smf_value_s;
	char const		*smf_value_e;

	/* Split query sender */
	char const		*smf_sender_mailbox_s;
	char const		*smf_sender_mailbox_e;
	char const		*smf_sender_domain_s;
	char const		*smf_sender_domain_e;

};

typedef void sm_marid_dns_result_callback(
	sm_marid *, int, char const * const *, size_t);

typedef struct sm_marid_arena sm_marid_arena;
struct sm_marid_arena;

#define	SM_MARID_CONTEXT_SET(c)		\
	 (  ((unsigned char *)(c))[0] = 0xf0 	\
	 ,  ((unsigned char *)(c))[1] = 0x05 	\
	 ,  ((unsigned char *)(c))[2] = 0xba 	\
	 ,  ((unsigned char *)(c))[3] = 0x11)

#define	SM_MARID_CONTEXT_CHECK(c)		\
	(   (c) != NULL				\
	 && ((unsigned char *)(c))[0] == 0xf0 	\
	 && ((unsigned char *)(c))[1] == 0x05 	\
	 && ((unsigned char *)(c))[2] == 0xba 	\
	 && ((unsigned char *)(c))[3] == 0x11)

struct sm_marid
{
	unsigned char		sm_magic[4];

	void			*sm_app_data;

	void			(*sm_app_free)(void *, void *);
	void			*(*sm_app_alloc)(void *, size_t);
	void			(*sm_app_log)(void *, int, char const *);

	struct sm_marid_arena	*sm_arena;
	sm_marid_frame		*sm_frame;

	/* Hostinfo used for macro expansion in "exp" strings. */
	char const		*sm_smtp_client_ip;
	char const		*sm_smtp_hostname;

	/* When making DNS requests, domain, type, and recipient. */
	char 			*sm_dns_domain;
	int			sm_dns_type;
	sm_marid_dns_result_callback	*sm_dns_result;

	int			sm_result;
	int			sm_reason;
	char const		*sm_explanation;

	/* 0 for no limit, otherwise maximum recursion depth. */
	size_t			sm_depth_max;

	/* 0 for no limit, otherwise # of requests */
	size_t			sm_request_max;
	size_t			sm_request_n;

	/* Which types do we accept? */
	char const * const *	sm_version_patterns;
};

typedef enum 
{
	SM_MARID_MODIFIER,
	SM_MARID_DIRECTIVE

} sm_marid_expression_type;

typedef struct
{
	sm_marid_expression_type	smx_type;

	/* Modifier: before the =.  Directive: before the : */
	char const			*smx_name_s;
	char const			*smx_name_e;

	/* Modifier: after the =.  Directive: after the : */
	char const			*smx_value_s;
	char const			*smx_value_e;

	/* Of interest for directives only. */
	char				smx_prefix;
	char const			*smx_cidr_s;
	char const			*smx_cidr_e;

} sm_marid_expression;

int sm_marid_is_fqdn(sm_marid *, char const *);
int sm_marid_memstrcaseeq(char const *, char const *, char const *);

/* sm-marid-address.c */

int sm_marid_address_split(sm_marid *context);

/* sm-marid-arena.c */

void *sm_marid_arena_alloc(sm_marid *, size_t);
void sm_marid_arena_destroy(sm_marid_arena *, void *, void (*)(void *, void *));
void * sm_marid_arena_memdup(sm_marid *, char const *, char const *);

/* sm-marid-dns.c */

void sm_marid_check_host_dns_query(
	sm_marid *, int, char const *, sm_marid_dns_result_callback *);
char * sm_marid_check_host_dns_skip_version_tag(
	sm_marid	*context,
	char const 	*s,
	size_t		n);

/* sm-marid-domain.c */

char const * sm_marid_domain_spec(
	sm_marid 	*context,
	char const	*domain_s,
	char const	*domain_e);
int sm_marid_domain_contains_or_is(char const *suffix, char const *domain);

/* sm-marid-evaluate.c */

char *sm_marid_evaluate(sm_marid *, char const *, char const *, int);

/* sm-marid-frame.c */

void sm_marid_check_host_deliver_result(sm_marid *);
int  sm_marid_check_host_run(sm_marid *);
sm_marid_frame * sm_marid_check_host_frame(
	sm_marid 		*_marid,
	char const		*_ip,
	char const		*_domain,
	char const		*_sender,
	sm_marid_deliver_result	*_deliver_result);

/* sm-marid-log.c */

void sm_marid_log(sm_marid *, sm_marid_loglevel, const char *fmt, ...);
#define	sm_marid_log_check(ctx, x)	((x) ? 1 : 	\
	  (sm_marid_log((ctx), SM_MARID_LOG_WARN,		\
	  	"%s:%d: assertion failed: %s", __FILE__, __LINE__, # x), 0))

/* sm-marid-record.c */

int sm_marid_check_host_record_modifiers(sm_marid *);
void sm_marid_check_host_record_continue(sm_marid *);

/* sm-marid-scan.c */

int sm_marid_scan_expression(char const**, char const *, sm_marid_expression *);
int sm_marid_scan_cidr(
	char const		*s,
	char const		**e_inout,
	size_t			*i4_out,
	size_t			*i6_out);

/* sm-marid-ip.c */

int sm_marid_ip_version(char const *, char const *);
int sm_marid_ip_eq(
	unsigned char const	*_a,
	unsigned char const	*_b,
	size_t			_n,
	size_t			_bits);

int sm_marid_ip_canon(char const *, char const *, unsigned char *, size_t *);

/* sm-marid.c */

void sm_marid_check_host_log_result(sm_marid *context);
void sm_marid_check_host_chain(sm_marid *_new, sm_marid *_old);

/* sm-marid-mod.c */

int sm_marid_mod_ignore(sm_marid *, sm_marid_expression const *);

/* sm-marid-mod-exp.c */

int sm_marid_mod_exp(sm_marid *, sm_marid_expression const *);
void sm_marid_mod_exp_execute(sm_marid *);

/* sm-marid-mod-redirect.c */

int sm_marid_mod_redirect(sm_marid *, sm_marid_expression const *);
void sm_marid_mod_redirect_execute(sm_marid *);

/* sm-marid-dir-all.c */

int sm_marid_dir_all(sm_marid *, sm_marid_expression const *);

/* sm-marid-dir-include.c */

int sm_marid_dir_include(sm_marid *, sm_marid_expression const *);

/* sm-marid-dir-a.c */

int sm_marid_dir_a(sm_marid *, sm_marid_expression const *);
int sm_marid_dir_mx(sm_marid *, sm_marid_expression const *);

/* sm-marid-dir-ip.c */

int sm_marid_dir_ip4(sm_marid *, sm_marid_expression const *);
int sm_marid_dir_ip6(sm_marid *, sm_marid_expression const *);

int sm_marid_dir_exists(sm_marid *, sm_marid_expression const *);
int sm_marid_dir_ptr(sm_marid *, sm_marid_expression const *);

#endif /* SM_MARIDP_H */
