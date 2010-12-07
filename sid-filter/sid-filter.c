/*
**  Copyright (c) 2004-2006, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**  Sendmail, Inc. Confidential
**
**  $Id: sid-filter.c,v 1.156 2008/05/27 20:04:36 msk Exp $
*/

#ifndef lint
static char sid_filter_c_id[] = "@(#)$Id: sid-filter.c,v 1.156 2008/05/27 20:04:36 msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#ifndef USE_ARLIB
# include <netdb.h>
#endif /* ! USE_ARLIB */
#ifdef SOLARIS
# if SOLARIS > 20700
#  include <iso/limits_iso.h>
# else /* SOLARIS > 20700 */
#  include <limits.h>
# endif /* SOLARIS > 20700 */
#endif /* SOLARIS */
#include <resolv.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <sysexits.h>
#include <unistd.h>
#include <pwd.h>
#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netdb.h>

#ifdef SOLARIS
# define _PATH_DEVNULL	"/dev/null"
#else /* SOLARIS */
# include <paths.h>
#endif /* SOLARIS */

/* sendmail includes */
#include <sm/cdefs.h>
#include <sm/string.h>

/* async resolver includes */
#ifdef USE_ARLIB
# include <ar.h>
#endif /* USE_ARLIB */

/* libmilter includes */
#ifndef DEBUG
# include <libmilter/mfapi.h>
#endif /* !DEBUG */

/* libmarid includes */
#include <sm-marid.h>

/* sid-filter includes */
#include "sid-filter.h"
#include "rfc2822.h"
#include "util.h"

/* MACROS */
#define	BUFRSZ		256
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T	char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T	unsigned char *
#endif /* __RES && __RES >= 19940415 */
#ifndef INADDR_NONE
# define INADDR_NONE	0xffffffff
#endif /* ! INADDR_NONE */
#define	JOBID(x)	((x) == NULL ? JOBIDUNKNOWN : (x))

#ifdef NO_SMFI_INSHEADER
# define smfi_insheader(w,x,y,z)	smfi_addheader((w), (y), (z))
# define ADDHEADERFUNCNAME		"smfi_addheader"
#else /* NO_SMFI_INSHEADER */
# define ADDHEADERFUNCNAME		"smfi_insheader"
#endif /* NO_SMFI_INSHEADER */

/* DEBUGGING STUFF */
#ifdef DEBUG
# define MI_SUCCESS	1
# define MI_FAILURE	(-1)
# define SMFIS_CONTINUE	0
# define SMFIS_ACCEPT	1
# define SMFIS_REJECT	2
# define SMFIS_DISCARD	3
# define SMFIS_TEMPFAIL	4
# define sfsistat	int
# define SMFICTX	void
# define _SOCK_ADDR	struct sockaddr

void *smfi_getpriv __P((void *));
char *smfi_getsymval __P((void *, char *));
int smfi_addheader __P((void *, char *, char *));
#ifndef NO_SMFI_INSHEADER
int smfi_insheader __P((void *, int, char *, char *));
#endif /* ! NO_SMFI_INSHEADER */
int smfi_replacebody __P((void *, char *, size_t));
int smfi_progress __P((void *));
void smfi_setconn __P((char *));
void smfi_setpriv __P((void *, void *));
int smfi_setreply __P((void *, char *, char *, char *));

char *smfis_ret[] =
{
	"SMFIS_CONTINUE",
	"SMFIS_ACCEPT",
	"SMFIS_REJECT",
	"SMFIS_DISCARD",
	"SMFIS_TEMPFAIL",
};
#endif /* DEBUG */

const char *bestguessspf[] =
{
	"v=spf1 a/24 mx/24 ptr ?all",
	NULL
};

/*
**  Header -- a handle referring to a header
*/

typedef struct Header * Header;
struct Header
{
	char *		hdr_hdr;
	char *		hdr_val;
	struct Header *	hdr_next;
};

/*
**  Context -- filter context
*/

typedef struct Context * Context;
struct Context
{
	bool		ctx_nopra;		/* no PRA found */
	Header		ctx_hqhead;		/* header queue head */
	Header		ctx_hqtail;		/* header queue tail */
	Header		ctx_pra;		/* PRA header */
	char *		ctx_jobid;		/* job ID */
	_SOCK_ADDR	ctx_addr;		/* client IP information */
	sm_marid *	ctx_marid;		/* libmarid handle */
	SMFICTX *	ctx_milter;		/* milter context */
	char		ctx_mariderr[BUFRSZ + 1];
						/* libmarid error buffer */
	char		ctx_sender[MAXADDRESS + 1];
						/* envelope sender */
	char		ctx_local[MAXADDRESS + 1];
						/* PRA local-part */
	char		ctx_domain[MAXHOSTNAMELEN + 1];
						/* PRA domain */
	char		ctx_hostname[MAXHOSTNAMELEN + 1];
						/* client hostname */
	char		ctx_lastquery[MAXHOSTNAMELEN + 1];
						/* previous query */
	unsigned char 	ctx_ansbuf[MARIDREPLIES][MAXPACKET];
						/* DNS answer buffer */
};

/* PROTOTYPES */
sfsistat mlfi_abort __P((SMFICTX *));
sfsistat mlfi_body __P((SMFICTX *, u_char *, size_t));
sfsistat mlfi_connect __P((SMFICTX *, char *, _SOCK_ADDR *));
sfsistat mlfi_envfrom __P((SMFICTX *, char **));
sfsistat mlfi_envrcpt __P((SMFICTX *, char **));
sfsistat mlfi_eoh __P((SMFICTX *));
sfsistat mlfi_eom __P((SMFICTX *));
sfsistat mlfi_header __P((SMFICTX *, char *, char *));

static void sid_msgcleanup __P((SMFICTX *));

/* SPF SCOPES */
#define	SM_SCOPE_SPF	0			/* SPF classic */
#define	SM_SCOPE_PRA	1			/* Sender ID */

/* GLOBALS */
bool addxhdr;					/* add identifying header? */
bool bestguess;					/* use best-guess SFP? */
bool die;					/* global "die" flag */
bool dolog;					/* syslog */
bool no_i_whine;				/* noted ${i} is undefined */
bool nopraspf1;					/* don't use SPF for PRA */
bool nopraok;					/* continue if no PRA found */
bool quiet;					/* quiet (less logging) */
bool testmode;					/* in test mode */
bool softdns;					/* softfail DNS errors */
bool quarantine;				/* quarantine vs. reject */
int diesig;					/* termination signal */
int rmode;					/* rejection mode */
int maridlog;					/* libmarid log level */
unsigned int tmo;				/* DNS timeout */
char *myname;					/* fake name */
char *progname;					/* program name */
char *rejectmsg;				/* rejection message */
char **domains;					/* list of domains to pass */
Peer peerlist;					/* queue of "peers" */
#if USE_ARLIB
AR_LIB ar;					/* async resolver handle */
#endif /* USE_ARLIB */

#ifdef DEBUG
static void *fakepriv;				/* fake private space */
#endif /* DEBUG */

#define	SID_DEBUG(x)	(getenv("SIDDEBUG") != NULL && \
			 strchr(getenv("SIDDEBUG"), (x)) != NULL)

#define	TRYFREE(x)	do { \
				if ((x) != NULL) \
				{ \
					free(x); \
					(x) = NULL; \
				} \
			} while (0)



/*
**  ==================================================================
**  BEGIN private section
*/

/*
**  SID_INITCONTEXT -- initialize filter context
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A pointer to an allocated and initialized filter context, or NULL
**  	on failure.
**
**  Side effects:
**  	Crop circles near Birmingham.
*/

static Context
sid_initcontext(void)
{
	struct Context *ctx;

	ctx = malloc(sizeof(struct Context));
	if (ctx == NULL)
		return NULL;

	memset(ctx, '\0', sizeof(struct Context));

	return ctx;
}

/*
**  SID_MSGCLEANUP -- release local resources related to a message
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	None.
*/

static void
sid_msgcleanup(SMFICTX *ctx)
{
	Context sic;

#ifndef DEBUG
	assert(ctx != NULL);
#endif /* !DEBUG */

	sic = (Context) smfi_getpriv(ctx);

	/* release memory */
	if (sic != NULL)
	{
		if (sic->ctx_hqhead != NULL)
		{
			Header hdr;
			Header prev;

			hdr = sic->ctx_hqhead;
			while (hdr != NULL)
			{
				TRYFREE(hdr->hdr_hdr);
				TRYFREE(hdr->hdr_val);
				prev = hdr;
				hdr = hdr->hdr_next;
				TRYFREE(prev);
			}

			sic->ctx_hqhead = NULL;
			sic->ctx_hqtail = NULL;
		}

		if (sic->ctx_marid != NULL)
		{
			sm_marid_destroy(sic->ctx_marid);
			sic->ctx_marid = NULL;
		}

		sic->ctx_nopra = FALSE;
	}
}

/*
**  SID_CONNCLEANUP -- release local resources related to a connection
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	None.
*/

static void
sid_conncleanup(SMFICTX *ctx)
{
	Context sic;

#ifndef DEBUG
	assert(ctx != NULL);
#endif /* !DEBUG */

	sic = (Context) smfi_getpriv(ctx);

	/* release memory */
	if (sic != NULL)
	{
		sid_msgcleanup(ctx);
		free(sic);
		smfi_setpriv(ctx, NULL);
	}
}

/*
**  SID_FINDHEADER -- find a header
**
**  Parameters:
**  	sic -- filter context
**  	hname -- name of the header of interest
**  	instance -- which instance is wanted (0 = first)
**
**  Return value:
**  	Header handle, or NULL if not found.
*/

Header
sid_findheader(Context sic, char *hname, int instance)
{
	Header hdr;

	assert(sic != NULL);
	assert(hname != NULL);

	hdr = sic->ctx_hqhead;

	while (hdr != NULL)
	{
		if (strcasecmp(hdr->hdr_hdr, hname) == 0)
		{
			if (instance == 0)
				return hdr;
			else
				instance--;
		}

		hdr = hdr->hdr_next;
	}

	return NULL;
}

/*
**  SID_GETPRA -- find the "purported responsible address"
**
**  Parameters:
**  	sic -- SenderID context
**
**  Return value:
**  	The HEADER that contains the PRA.
*/

static Header
sid_getpra(Context sic)
{
	bool malformed = FALSE;
	Header f = NULL;
	Header hdr;
	Header pra = NULL;
	Header r = NULL;
	Header rf = NULL;
	Header s = NULL;

	assert(sic != NULL);

	/*
	**  This is directly based on section 4 of draft-ietf-marid-core-02.
	*/

	/*
	**  1. Locate the first non-empty Resent-Sender header in the message.
	**  If no such header is found, continue with step 2.  If it is   
	**  preceded by a non-empty Resent-From header and one or more
	**  Received or Return-Path headers occur after said Resent-From  
	**  header and before the Resent-Sender header, continue with step
	**  2.  Otherwise, proceed to step 5.
	*/

	for (hdr = sic->ctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if (strcasecmp(hdr->hdr_hdr, RESENTFROMHDR) == 0 &&
		    strlen(hdr->hdr_val) > 0)
		{
			rf = hdr;
			continue;
		}

		if ((strcasecmp(hdr->hdr_hdr, RETURNPATHHDR) == 0 ||
		     strcasecmp(hdr->hdr_hdr, RECEIVEDHDR) == 0) && 
		     strlen(hdr->hdr_val) > 0 &&
		     rf != NULL)
		{
			r = hdr;
			continue;
		}

		if (strcasecmp(hdr->hdr_hdr, RESENTSENDERHDR) == 0 &&
		     strlen(hdr->hdr_val) > 0 &&
		     r != NULL && rf != NULL)
		{
			pra = hdr;
			break;
		}
	}

	/*
	**  2. Locate the first non-empty Resent-From header in the message.
	**  If a Resent-From header is found, proceed to step 5. Otherwise,
	**  continue with step 3.
	*/

	if (pra == NULL && rf != NULL)
		pra = rf;

	/*
	**  3. Locate all the non-empty Sender headers in the message.  If   
	**  there are no such headers, continue with step 4.  If there is   
	**  exactly one such header, proceed to step 5.  If there is more
	**  than one such header, proceed to step 6.
	*/

	for (hdr = sic->ctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if (strcasecmp(hdr->hdr_hdr, SENDERHDR) == 0)
		{
			if (s == NULL)
				s = hdr;
			else
				malformed = TRUE;
		}
	}

	if (!malformed && s != NULL && pra == NULL)
		pra = s;

	/*
	**  4. Locate all the non-empty From headers in the message.  If there
	**  is exactly one such header, continue with step 5.  Otherwise,
	**  proceed to step 6.
	*/

	for (hdr = sic->ctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if (strcasecmp(hdr->hdr_hdr, FROMHDR) == 0)
		{
			if (f == NULL)
				f = hdr;
			else
				malformed = TRUE;
		}
	}

	if (!malformed && f != NULL && pra == NULL)
		pra = f;

	/*
	**  6. The message is ill-formed, and it is impossible to determine a
	**  Purported Responsible Address.  MTAs performing the Sender ID
	**  check as part of receiving a message SHOULD reject that message
	**  with "550 5.1.7 Missing Purported Responsible Address".
	*/

	if (malformed || pra == NULL)
		return NULL;

	/*
	**  5. A previous step has selected a single header from the message.
	**  If that header is malformed (e.g. it appears to contain multiple
	**  mailboxes, or the single mailbox is hopelessly malformed, or the
	**  single mailbox does not contain a domain name), continue with
	**  step 6.  Otherwise, return that single mailbox as the Purported
	**  Responsible Address.
	**
	**  XXX -- done by the caller for now
	*/

	return pra;
}

/*
**  SID_MARID_LOG -- handle a log message from libmarid
**
**  Parameters:
**  	data -- application data
**  	level -- log level
**  	text -- text to log
**
**  Return value:
**  	None.
*/

void
sid_marid_log(void *data, int level, char const *text)
{
	Context sic;

	assert(data != NULL);
	assert(text != NULL);

	sic = data;

	sm_strlcpy(sic->ctx_mariderr, text, sizeof sic->ctx_mariderr);

	if (maridlog >= level)
	{
		char *jobid;

		if (sic->ctx_jobid == NULL)
			jobid = MSGIDUNKNOWN;
		else
			jobid = sic->ctx_jobid;

		syslog(LOG_DEBUG, "%s %s", jobid, text);
	}
}

/*
**  SID_DECODE_A -- decode a DNS reply, expecting to find an A record
**
**  Parameters:
**  	ansbuf -- answer buffer
**  	anslen -- size of answer buffer
**  	rcount -- pointer to current answer count
**  	mreplies -- pointer to MARID reply array
**  
**  Return value:
**  	None.
*/

void
sid_decode_a(unsigned char *ansbuf, size_t anslen, int *rcount,
             char **mreplies)
{
	int qdcount;
	int ancount;
	int type;
	int class;
	int n;
	unsigned char *cp;
	unsigned char *eom;
	char qname[MAXHOSTNAMELEN + 1];
	struct in_addr addr;
	HEADER hdr;

	assert(ansbuf != NULL);
	assert(rcount != NULL);
	assert(mreplies != NULL);

	if (*rcount >= MARIDREPLIES)
		return;

	memcpy(&hdr, ansbuf, sizeof hdr);
	cp = (unsigned char *) ansbuf + HFIXEDSZ;
	eom = (unsigned char *) ansbuf + anslen;

	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		(void) dn_expand((unsigned char *) ansbuf, eom, cp,
		                 qname, sizeof qname);

		if ((n = dn_skipname(cp, eom)) < 0)
			return;

		cp += n;

		/* extract type and class */
		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (hdr.rcode == NXDOMAIN)
		return;

	ancount = ntohs((unsigned short) hdr.ancount);
	while (ancount > 0 && *rcount < MARIDREPLIES)
	{
		if ((n = dn_expand((unsigned char *) ansbuf, eom, cp,
		                   (RES_UNC_T) qname,
		                   sizeof qname)) < 0)
			return;
		cp += n;

		if (cp + INT16SZ + INT16SZ > eom)
			return;
		GETSHORT(type, cp);
		GETSHORT(class, cp);

		if (type != T_A || class != C_IN)
			return;

		/* skip TTL */
		cp += INT32SZ;

		/* get payload length */
		if (cp + INT16SZ > eom)
			return;
		GETSHORT(n, cp);

		/* make sure it's enough */
		if (n < INT32SZ)
			return;

		memcpy(&addr.s_addr, cp, INT32SZ);
		cp += INT32SZ;
		/* XXX -- not thread-safe! (yet) */
		sm_strlcpy(mreplies[*rcount], inet_ntoa(addr),
		           MARIDREPLYSZ);

		*rcount = *rcount + 1;
		ancount--;
	}
}

/*
**  SID_MARID_CHECK -- run a MARID check
**
**  Parameters:
**  	sic -- Sender-ID context
**  	scope -- scope to check; should be an SM_SCOPE_* constant
**  	ip -- IP address of client as a string
**  	addr -- address to check
**  	result -- result code (returned)
**  	reason -- reason code (returned)
**  	expl -- explanation string (returned)
**
**  Return value:
**  	0 -- success
**  	-1 -- miscellaneous error
**  	-2 -- resolver error or DNS reply garbled
*/

static int
sid_marid_check(Context sic, int scope, char *ip, char *addr, int *result,
                int *reason, const char **expl)
{
	int status;
	int type;
	int class;
	int rtype;
	int mtype;
	int rcount;
	int queries;
	int qdcount;
	int ancount;
	int m;
	int n;
	int s;
	int nmx;
	size_t anslen;
	const char *dd;
	char *at;
	unsigned char *eom;
	unsigned char *cp;
	unsigned char *p;
#if USE_ARLIB
	AR_QUERY q[MARIDREPLIES];
	int error[MARIDREPLIES];
#endif /* USE_ARLIB */
	char *rptrs[MARIDREPLIES];
	int prec[MAXMXSETSZ];
	char mreplies[MARIDREPLIES][MARIDREPLYSZ];
	char qname[MAXHOSTNAMELEN + 1];
	char mxes[MAXMXSETSZ][MAXHOSTNAMELEN + 1];
	char policy[MARIDREPLYSZ];
#if USE_ARLIB
	struct timeval timeout;
#endif /* USE_ARLIB */
	struct in_addr inaddr;
	HEADER hdr;

	assert(sic != NULL);
	assert(ip != NULL);
	assert(scope == SM_SCOPE_PRA || scope == SM_SCOPE_SPF);
	assert(addr != NULL);
	assert(result != NULL);
	assert(reason != NULL);
	assert(expl != NULL);

	queries = 0;

	/* allocate MARID handle */
	sic->ctx_marid = sm_marid_new(sic, sid_marid_log, NULL, NULL);
	if (sic->ctx_marid == NULL)
	{
		if (dolog)
		{
			syslog(LOG_ERR, "%s sm_marid_new() failed",
			       sic->ctx_jobid);
		}

		return -1;
	}

	/* set some limits */
	(void) sm_marid_set_max_depth(sic->ctx_marid, MAXDEPTH);

	at = strchr(addr, '@');
	if (at == NULL)
		return -1;

#if DEBUG
	printf("*** sm_marid_check_host(*, `%s', `%s', `%s')\n",
	       ip, at + 1, addr);
#endif /* DEBUG */
	status = sm_marid_check_host(sic->ctx_marid, ip, at + 1, addr);
	if (status != 0)
		return status;

	/* build the pointer array */
	for (n = 0; n < MARIDREPLIES; n++)
		rptrs[n] = mreplies[n];

	/* handle recursions */
	while ((dd = sm_marid_request(sic->ctx_marid, &mtype)) != NULL)
	{
		queries++;

		memset(mreplies, '\0', sizeof mreplies);
		memset(mxes, '\0', sizeof mxes);
		memset(prec, '\0', sizeof prec);
		memset(policy, '\0', sizeof policy);
		rcount = 0;
		nmx = 0;

		/* type translation */
		switch (mtype)
		{
		  case SM_MARID_TXT:
		  case SM_MARID_MARID:
			type = T_TXT;
			break;

		  case SM_MARID_ADDR:
		  case SM_MARID_A:
			type = T_A;
			break;

		  case SM_MARID_MX:
			type = T_MX;
			break;

		  case SM_MARID_PTR:
			type = T_PTR;
			break;

		  default:
			if (dolog)
			{
				syslog(LOG_ERR,
				       "%s sm_marid_request(): unexpected type request (%d)",
				       sic->ctx_jobid, mtype);
			}

			return -1;
		}

		if (type == T_PTR)
		{
			u_char *ab;
			struct in_addr addr;

			addr.s_addr = inet_addr(dd);
			ab = (u_char *) &addr;
			snprintf(qname, sizeof qname,
			         "%u.%u.%u.%u.%s",
			         ab[3], ab[2], ab[1], ab[0],
			         INADDRDOMAIN);
		}
		else
		{
			sm_strlcpy(qname, dd, sizeof qname);
		}

		snprintf(sic->ctx_lastquery, sizeof sic->ctx_lastquery,
		         "%s %d", qname, type);

#if DEBUG
		printf(">>> %s\n", sic->ctx_lastquery);
#endif /* DEBUG */

#if USE_ARLIB
		timeout.tv_sec = tmo;
		timeout.tv_usec = 0;
		errno = 0;
		q[0] = ar_addquery(ar, qname, C_IN, type, MAXCNAMEDEPTH,
		                   sic->ctx_ansbuf[0],
		                   sizeof sic->ctx_ansbuf[0], &error[0],
		                   tmo == 0 ? NULL : &timeout);
		if (q[0] == NULL)
		{
			if (dolog)
			{
				syslog(LOG_ERR, "%s ar_addquery() failed: %s",
				       sic->ctx_jobid, ar_strerror(error[0]));
			}

			*expl = ar_strerror(error[0]);

			return -2;
		}

		for (;;)
		{
			timeout.tv_sec = REPLYWAIT;
			timeout.tv_usec = 0;

			status = ar_waitreply(ar, q[0], NULL, &timeout);

			if (status != AR_STAT_NOREPLY)
				break;

			(void) smfi_progress(sic->ctx_milter);
		}

		(void) ar_cancelquery(ar, q[0]);

		if (status == AR_STAT_ERROR)
		{
			if (dolog)
			{
				syslog(LOG_ERR, "%s ar_waitreply() failed: %s",
				       sic->ctx_jobid, ar_strerror(error[0]));
			}

			*expl = ar_strerror(error[0]);

			return -2;
		}
		else if (status == AR_STAT_EXPIRED)
		{
			if (dolog)
			{
				syslog(LOG_ERR, "%s DNS timeout (%d %s)",
				       sic->ctx_jobid, type, dd);
			}

			*expl = "DNS timeout";

			return -2;
		}
#else /* USE_ARLIB */
		status = res_query(qname, C_IN, type, sic->ctx_ansbuf[0],
		                   sizeof sic->ctx_ansbuf[0]);
		if (status == -1)
		{
			char *txt;

			switch (h_errno)
			{
			  case HOST_NOT_FOUND:
				if (bestguess && type == T_TXT)
				{
					sm_marid_request_result(sic->ctx_marid,
					                        0,
					                        bestguessspf,
					                        1);
				}
				else
				{
					sm_marid_request_result(sic->ctx_marid,
					                        SM_MARID_ERR_NXDOMAIN,
					                        (const char **) rptrs,
					                        0);
				}
				continue;

			  case NO_DATA:
				sm_marid_request_result(sic->ctx_marid, 0,
				                        (const char **) rptrs,
				                        0);
				continue;

			  case TRY_AGAIN:
			  case NO_RECOVERY:
			  default:
				switch (h_errno)
				{
				  case TRY_AGAIN:
					txt = "resolver returned TRY_AGAIN";
					break;

				  case NO_RECOVERY:
					txt = "resolver returned NO_RECOVERY";
					break;

				  default:
					txt = "resolver returned unknown error";
					break;
				}

				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s res_query() failed (%s)",
					       sic->ctx_jobid, txt);
				}

				*expl = txt;

				return -2;
			}
		}
#endif /* USE_ARLIB */

		/* decode the reply */
		anslen = sizeof sic->ctx_ansbuf[0];
		memcpy(&hdr, sic->ctx_ansbuf[0], sizeof hdr);
		cp = (unsigned char *) sic->ctx_ansbuf[0] + HFIXEDSZ;
		eom = (unsigned char *) sic->ctx_ansbuf[0] + anslen;

		for (qdcount = ntohs((unsigned short) hdr.qdcount);
		     qdcount > 0;
		     qdcount--)
		{
			(void) dn_expand((unsigned char *) sic->ctx_ansbuf[0],
			                 eom, cp, qname, sizeof qname);

			if ((n = dn_skipname(cp, eom)) < 0)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s DNS reply garbled (%d %s)",
					       sic->ctx_jobid, type, dd);
				}

				*expl = "DNS reply garbled";

				return -2;
			}

			cp += n;

			/* extract type and class */
			GETSHORT(rtype, cp);
			GETSHORT(class, cp);
		}

		if (rtype != type || class != C_IN)
		{
			if (dolog)
			{
				syslog(LOG_ERR,
				       "%s DNS reply garbled (%d %s)",
				       sic->ctx_jobid, type, dd);
			}

			*expl = "DNS reply garbled";

			return -2;
		}

		ancount = ntohs((unsigned short) hdr.ancount);

		if (hdr.rcode == NXDOMAIN)
		{
#if DEBUG
			printf("<<< NXDOMAIN\n");
#endif /* DEBUG */
			if (bestguess && type == T_TXT)
			{
				sm_marid_request_result(sic->ctx_marid, 0,
				                        bestguessspf, 1);
			}
			else
			{
				sm_marid_request_result(sic->ctx_marid,
				                        SM_MARID_ERR_NXDOMAIN,
				                        (const char **) rptrs,
				                        0);
			}

			continue;
		}

		while (ancount > 0 && rcount < MARIDREPLIES)
		{
			if ((n = dn_expand((unsigned char *) sic->ctx_ansbuf[0],
			                   eom, cp, (RES_UNC_T) qname,
			                   sizeof qname)) < 0)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s DNS reply garbled (%d %s)",
					       sic->ctx_jobid, type, dd);
				}

				*expl = "DNS reply garbled";

				return -2;
			}
			cp += n;

			if (cp + INT16SZ + INT16SZ > eom)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s DNS reply garbled (%d %s)",
					       sic->ctx_jobid, type, dd);
				}

				*expl = "DNS reply garbled";

				return -2;
			}
			GETSHORT(rtype, cp);
			GETSHORT(class, cp);

			if (rtype != type || class != C_IN)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s DNS reply garbled (%d %s)",
					       sic->ctx_jobid, type, dd);
				}

				*expl = "DNS reply garbled";

				return -2;
			}

			/* skip TTL */
			cp += INT32SZ;

			/* get payload length */
			if (cp + INT16SZ > eom)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s DNS reply garbled (%d %s)",
					       sic->ctx_jobid, type, dd);
				}

				*expl = "DNS reply garbled";

				return -2;
			}
			GETSHORT(n, cp);

			if (cp + n > eom)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s DNS reply garbled (%d %s)",
					       sic->ctx_jobid, type, dd);
				}

				*expl = "DNS reply garbled";

				return -2;
			}

			/* the dirty work */
			switch (rtype)
			{
			  case T_TXT:
				p = &mreplies[rcount][0];
				m = 0;
				s = MARIDREPLYSZ;
				while (n > 0)
				{
					if (m == 0)
					{
						m = *cp;
					}
					else
					{
						if (s > 0)
						{
							*p = *cp;
							p++;
							s--;
						}
						m--;
					}
					cp++;
					n--;
				}
				break;

			  case T_MX:
				if (cp + INT16SZ > eom)
				{
					if (dolog)
					{
						syslog(LOG_ERR,
						       "%s DNS reply garbled (%d %s)",
						       sic->ctx_jobid, type,
						       dd);
					}
	
					*expl = "DNS reply garbled";

					return -2;
				}

				/* skip if there were too many */
				if (nmx >= MAXMXSETSZ)
				{
					char junk[MAXHOSTNAMELEN];

					cp += INT16SZ;
					n = dn_expand((u_char *) sic->ctx_ansbuf[0],
					              eom, cp, junk,
					              MAXHOSTNAMELEN);
					if (n >= 0)
						cp += n;
					break;
				}

				/* precedence */
				GETSHORT(prec[nmx], cp);

				n = dn_expand((u_char *) sic->ctx_ansbuf[0],
				              eom, cp, (RES_UNC_T) mxes[nmx],
				              MAXHOSTNAMELEN);
				if (n < 0)
				{
					if (dolog)
					{
						syslog(LOG_ERR,
						       "%s DNS reply garbled (%d %s)",
						       sic->ctx_jobid, type,
						       dd);
					}
	
					*expl = "DNS reply garbled";

					return -2;
				}
				cp += n;
				nmx++;
				break;

			  case T_A:
				memcpy(&inaddr.s_addr, cp, INT32SZ);
				cp += INT32SZ;
				/* XXX -- not thread-safe! (yet) */
				sm_strlcpy(mreplies[rcount], inet_ntoa(inaddr),
				           MARIDREPLYSZ);
				break;

			  case T_PTR:
				m = dn_expand((u_char *) sic->ctx_ansbuf[0],
				              eom, cp,
				              (RES_UNC_T) mreplies[rcount],
				              MARIDREPLYSZ);
				if (m < 0)
				{
					if (dolog)
					{
						syslog(LOG_ERR,
						       "%s DNS reply garbled (%d %s)",
						       sic->ctx_jobid, type,
						       dd);
					}
	
					*expl = "DNS reply garbled";

					return -2;
				}
				cp += n;
				break;

			  default:
				/* shouldn't happen */
				assert(0);
			}

#ifdef _FFR_NH_MFROM
			/*
			**  Using spf1 records for PRA checks is highly
			**  controversial because an SPF1 record written
			**  for mfrom checks could cause havoc if used for
			**  PRA checks.  However, most of this havoc is
			**  similar to what SPF does to mail forwarders.
			*/

			if (scope == SM_SCOPE_PRA)
			{
				/*
				**  Discard spf2.0/mfrom records whether "-n"
				**  was specified or not.  They are explicitly
				**  intended not to be for pra checks.
				*/

				if (strncasecmp(mreplies[rcount],
				                "spf2.0/mfrom ", 13) == 0)
				{
					memset(mreplies[rcount], '\0',
					       sizeof mreplies[rcount]);
				}

				/*
				**  Discard v=spf1 records if "-n" was
				**  specified.  They are not designed for PRA
				**  checks but don't explicitly exclude PRA.
				*/

				if (nopraspf1 &&
				    strncmp(mreplies[rcount],
				            "v=spf1", 6) == 0)
				{
					memset(mreplies[rcount], '\0',
					       sizeof mreplies[rcount]);
				}
			}
			else if (scope == SM_SCOPE_SPF)
			{
				/*
				**  Discard spf2.0/pra records that do not
				**  include mfrom.
				*/

				if (strncasecmp(mreplies[rcount],
				                "spf2.0/pra ", 11) == 0)
				{
					memset(mreplies[rcount], '\0',
					       sizeof mreplies[rcount]);
				}
			}
#endif /* _FFR_NH_MFROM */

			/* special handling for policy records */
			if (rtype == T_TXT)
			{
				switch (scope)
				{
				  case SM_SCOPE_PRA:
#ifdef _FFR_NH_MFROM
					if ((strncasecmp(mreplies[rcount],
					                 "spf2.0/pra",
					                 10) == 0) ||
					    (strncasecmp(mreplies[rcount],
					                 "spf2.0/mfrom,pra",
					                 16) == 0))
#else /* _FFR_NH_MFROM */
					if (strncasecmp(mreplies[rcount],
					                "spf2.0/pra", 10) == 0)
#endif /* _FFR_NH_MFROM */
					{
						sm_strlcpy(policy,
						           mreplies[rcount],
						           sizeof policy);
					}
					else if (!nopraspf1 &&
					         (strncasecmp(mreplies[rcount],
					                      "v=spf1", 6) == 0) &&
					         policy[0] == '\0')
					{
						sm_strlcpy(policy,
						           mreplies[rcount],
						           sizeof policy);
					}
					break;

				  case SM_SCOPE_SPF:
#ifdef _FFR_NH_MFROM
					/*
					**  This will tread on politics in
					**  some quarters, but there's little
					**  doubt about what domains with
					**  "spf2.0/mfrom" records intend.
					**  Some domains with them have
					**  "v=spf1" records also, so
					**  allowing duplications is also
					**  necessary.
					*/

					if ((strncasecmp(mreplies[rcount],
					                 "spf2.0/mfrom",
					                 12) == 0) ||
					    (strncasecmp(mreplies[rcount],
					                 "spf2.0/pra,mfrom",
					                 16) == 0))
					{
						sm_strlcpy(policy,
						           mreplies[rcount],
						           sizeof policy);
					}
					else if (strncasecmp(mreplies[rcount],
					                     "v=spf1",
					                     6) == 0 &&
					         policy[0] == '\0')
					{
						sm_strlcpy(policy,
						           mreplies[rcount],
						           sizeof policy);
					}
#else /* _FFR_NH_MFROM */
					if (strncasecmp(mreplies[rcount],
					                "v=spf1", 6) == 0)
					{
						sm_strlcpy(policy,
						           mreplies[rcount],
						           sizeof policy);
					}
#endif /* _FFR_NH_MFROM */
					break;

				  default:
					assert(0);
				}
			}

			rcount++;
			ancount--;
		}

		/* if there were MX replies, we are replacing the results */
		if (nmx > 0)
			rcount = 0;

		/* sort MX list */
		for (n = 0; n < nmx - 1; n++)
		{
			if (prec[n] > prec[n + 1])
			{
				m = prec[n];
				prec[n] = prec[n + 1];
				prec[n + 1] = m;

				sm_strlcpy(qname, mxes[n], sizeof qname);
				sm_strlcpy(mxes[n], mxes[n + 1],
				           sizeof mxes[n]);
				sm_strlcpy(mxes[n + 1], qname,
				           sizeof mxes[n + 1]);
			}
		}

		/* execute subsidiary queries if needed */
		for (n = 0; n < nmx; n++)
		{
#if USE_ARLIB
			timeout.tv_sec = tmo;
			timeout.tv_usec = 0;
			errno = 0;
			q[n] = ar_addquery(ar, mxes[n], C_IN, T_A,
			                   MAXCNAMEDEPTH, sic->ctx_ansbuf[n],
			                   sizeof sic->ctx_ansbuf[n],
			                   &error[n],
			                   tmo == 0 ? NULL : &timeout);
			if (q[n] == NULL)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s ar_addquery() failed: %s",
					       sic->ctx_jobid,
					       ar_strerror(error[n]));
				}

				for (m = 0; m < n; m++)
					(void) ar_cancelquery(ar, q[m]);

				*expl = ar_strerror(error[n]);

				return -2;
			}
#else /* USE_ARLIB */
			status = res_query(mxes[n], C_IN, T_A,
			                   sic->ctx_ansbuf[n],
			                   sizeof sic->ctx_ansbuf[n]);
			if (status == -1)
			{
				char *txt;

				switch (h_errno)
				{
				  case HOST_NOT_FOUND:
				  case NO_DATA:
					continue;

				  case NO_RECOVERY:
				  case TRY_AGAIN:
				  default:
					switch (h_errno)
					{
					  case TRY_AGAIN:
						txt = "TRY_AGAIN";
						break;

					  case NO_RECOVERY:
						txt = "NO_RECOVERY";
						break;

					  default:
						txt = "unknown";
						break;
					}

					if (dolog)
					{
						syslog(LOG_ERR,
						       "%s res_query() failed (%s)",
						       sic->ctx_jobid, txt);
					}

					return -2;
				}
			}
#endif /* USE_ARLIB */
		}

		for (n = 0; n < nmx; n++)
		{
#if USE_ARLIB
			for (;;)
			{
				timeout.tv_sec = REPLYWAIT;
				timeout.tv_usec = 0;

				status = ar_waitreply(ar, q[n], NULL,
				                      &timeout);

				if (status != AR_STAT_NOREPLY)
					break;

				(void) smfi_progress(sic->ctx_milter);
			}

			(void) ar_cancelquery(ar, q[n]);

			if (status == AR_STAT_ERROR)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s ar_waitreply() failed: %s",
					       sic->ctx_jobid,
					       ar_strerror(error[n]));
				}

				/* cancel all other queries */
				for (m = n + 1; m < nmx; m++)
					(void) ar_cancelquery(ar, q[m]);

				*expl = ar_strerror(error[n]);

				return -2;
			}
			else if (status == AR_STAT_EXPIRED)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s DNS timeout (%d %s)",
					       sic->ctx_jobid, type, dd);
				}

				/* cancel all other queries */
				for (m = n + 1; m < nmx; m++)
					(void) ar_cancelquery(ar, q[m]);

				*expl = "DNS timeout";

				return -2;
			}
#endif /* USE_ARLIB */

			sid_decode_a(sic->ctx_ansbuf[n],
			             sizeof sic->ctx_ansbuf[n], &rcount,
			             rptrs);
		}

		/* if this is a policy query, report only the right policy */
		if (mtype == SM_MARID_MARID && policy[0] != '\0')
		{
			sm_strlcpy(mreplies[0], policy, sizeof mreplies[0]);
			rcount = 1;
		}

		/* deliver the results */
#if DEBUG
		printf("<<< %d result%s\n", rcount, rcount == 1 ? "" : "s");
		for (n = 0; n < rcount; n++)
			printf("\t%s\n", rptrs[n]);
#endif /* DEBUG */

		sm_marid_request_result(sic->ctx_marid, 0,
		                        (const char **) rptrs, rcount);
	}

	*result = sm_marid_check_host_result(sic->ctx_marid, reason, expl);

#if DEBUG
	printf("*** result = %d, reason = %d, expl=`%s'\n",
	       *result, *reason, *expl == NULL ? "(null)" : *expl);
#endif /* DEBUG */

	/* free and clear sic->ctx_marid */
	sm_marid_destroy(sic->ctx_marid);
	sic->ctx_marid = NULL;

	return 0;
}

/*
**  SID_KILLCHILD -- signal a child process
**
**  Parameters:
**  	pid -- process ID to signal
**  	sig -- signal to use
**
**  Return value:
**  	None.
*/

static void
sid_killchild(pid_t pid, int sig)
{
	if (kill(pid, sig) == -1 && dolog)
	{
		syslog(LOG_ERR, "kill(%d, %d): %s", pid, sig,
		       strerror(errno));
	}
}

/*
**  SID_SIGHANDLER -- simple signal handler
**
**  Parameters:
**  	sig -- signal received
**
**  Return value:
**  	None.
*/

static void
sid_sighandler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM || sig == SIGHUP)
	{
		diesig = sig;
		die = TRUE;
	}
}

/*
**  SID_STDIO -- set up standard I/O descriptors and stuff in a child
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
**
**  Side effects:
**  	stdin, stdout and stderr are routed to /dev/null and the process
**  	starts running in its own process group.
*/

static void
sid_stdio(void)
{
	int devnull;

	/* this only fails silently, but that's OK */
	devnull = open(_PATH_DEVNULL, O_RDWR, 0);
	if (devnull != -1)
	{
		(void) dup2(devnull, 0);
		(void) dup2(devnull, 1);
		(void) dup2(devnull, 2);
		(void) close(devnull);
	}

	(void) setsid();
}

/*
**  SID_STAT_HEADER -- update status header
**
**  Parameters:
**
**  Return value:
**  	None.
*/

static void
sid_stat_header(int result, int reason, const char *expl, char *stathdr,
                size_t len)
{
	size_t hlen;
	char *txt;

	switch (result)
	{
	  case SM_MARID_NONE:
		sm_strlcat(stathdr, "none", len);
		break;

	  case SM_MARID_NEUTRAL:
		sm_strlcat(stathdr, "neutral", len);
		break;

	  case SM_MARID_PASS:
		sm_strlcat(stathdr, "pass", len);
		break;

	  case SM_MARID_FAIL:
		txt = NULL;
		switch (reason)
		{
		  case SM_MARID_NOT_PERMITTED:
			txt = "NotPermitted";
			break;

		  case SM_MARID_MALFORMED_DOMAIN:
			txt = "MalformedDomain";
			break;

		  case SM_MARID_DOMAIN_DOES_NOT_EXIST:
			txt = "DomainDoesNotExist";
			break;

		  default:
			break;
		}

		hlen = strlen(stathdr);
		if (txt != NULL)
		{
			snprintf(stathdr + hlen, len - hlen,
			         "fail (%s)", txt);
		}
		else
		{
			snprintf(stathdr + hlen, len + hlen,
			         "fail (reason code %d)", reason);
		}
		break;

	  case SM_MARID_SOFT_FAIL:
		sm_strlcat(stathdr, "softfail", len);
		break;

	  case SM_MARID_PERM_ERROR:
		sm_strlcat(stathdr, "permerror", len);
		break;

	  case SM_MARID_TEMP_ERROR:
	  default:
		sm_strlcat(stathdr, "temperror", len);
		break;
	}

	if (expl != NULL && expl[0] != '\0')
	{
		sm_strlcat(stathdr, " (", len);
		sm_strlcat(stathdr, expl, len);
		sm_strlcat(stathdr, ")", len);
	}
}

/*
**  END private section
**  ==================================================================
**  BEGIN milter section
*/

#if SMFI_VERSION >= 0x01000000
/*
**  MLFI_NEGOTIATE -- handler called on new SMTP connection to negotiate
**                    MTA options
**
**  Parameters:
**  	ctx -- milter context
**	f0  -- actions offered by the MTA
**	f1  -- protocol steps offered by the MTA
**	f2  -- reserved for future extensions
**	f3  -- reserved for future extensions
**	pf0 -- actions requested by the milter
**	pf1 -- protocol steps requested by the milter
**	pf2 -- reserved for future extensions
**	pf3 -- reserved for future extensions
**
**  Return value:
**  	An SMFIS_* constant.
*/

static sfsistat
mlfi_negotiate(SMFICTX *ctx,
               unsigned long f0,
               unsigned long f1,
               SM_UNUSED(unsigned long f2),
               SM_UNUSED(unsigned long f3),
               unsigned long *pf0,
               unsigned long *pf1,
               unsigned long *pf2,
               unsigned long *pf3)
{
	unsigned long reqactions = SMFIF_ADDHDRS;
	unsigned long wantactions = SMFIF_SETSYMLIST;
	unsigned long protosteps = (SMFIP_NOHELO |
	                            SMFIP_NOUNKNOWN |
	                            SMFIP_NORCPT |
	                            SMFIP_NODATA |
	                            SMFIP_NOBODY);

	/* verify the actions we need are available */
	if (quarantine)
		reqactions |= SMFIF_QUARANTINE;

	if ((f0 & reqactions) != reqactions)
	{
		if (dolog)
		{
			syslog(LOG_ERR,
			       "mlfi_negotiate(): required milter action(s) not available (got 0x%lx, need 0x%lx)",
			       f0, reqactions);
		}

		return SMFIS_REJECT;
	}

	/* also try to get some nice features */
	wantactions = (wantactions & f0);

	/* set the actions we want */
	*pf0 = (reqactions | wantactions);

	/* disable as many protocol steps we don't need as are available */
	*pf1 = (protosteps & f1);
	*pf2 = 0;
	*pf3 = 0;

	return SMFIS_CONTINUE;
}
#endif /* SMFI_VERSION >= 0x01000000 */

/*
**  MLFI_CONNECT -- connection handler
**
**  Parameters:
**  	ctx -- milter context
**  	host -- hostname
**  	ip -- address, in in_addr form
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_connect(SMFICTX *ctx, char *host, _SOCK_ADDR *ip)
{
	Context sic;

	/* if the client is on an ignored host, then ignore it */
	if (peerlist != NULL)
	{
		/* try hostname, if available */
		if (host != NULL && host[0] != '\0' && host[0] != '[')
		{
			sid_lowercase(host);
			if (sid_checkhost(peerlist, host))
				return SMFIS_ACCEPT;
		}

		/* try IP address, if available */
		if (ip != NULL && ip->sa_family == AF_INET)
		{
			if (sid_checkip(peerlist, ip))
				return SMFIS_ACCEPT;
		}
	}

	/* XXX -- queue up a PTR query, in case this host has lots of aliases */

	/*
	**  Initialize a context
	*/

	sic = sid_initcontext();
	if (sic == NULL)
	{
		if (dolog)
		{
			syslog(LOG_INFO,
			       "messages requeueing (internal error)");
		}

		return SMFIS_TEMPFAIL;
	}

	sic->ctx_milter = ctx;

	sm_strlcpy(sic->ctx_hostname, host, sizeof sic->ctx_hostname);
	if (ip != NULL)
	{
		memcpy(&sic->ctx_addr, ip, sizeof sic->ctx_addr);
	}
	else
	{
		struct sockaddr_in sin;

		memset(&sin, '\0', sizeof sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		memcpy(&sic->ctx_addr, &sin, sizeof sic->ctx_addr);
	}

	/*
	**  Save it in this thread's private space.
	*/

	smfi_setpriv(ctx, sic);

	return SMFIS_CONTINUE;
}

/*
**  MLFI_ENVFROM -- handler for MAIL FROM command (start of message)
**
**  Parameters:
**  	ctx -- milter context
**  	envfrom -- envelope from arguments
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	int err;
	char *user;
	char *domain;
	Context sic;

#ifndef DEBUG
	assert(ctx != NULL);
	assert(envfrom != NULL);
#endif /* !DEBUG */

	sic = smfi_getpriv(ctx);
	assert(sic != NULL);

	/*
	**  Clean up any message information that was there before.
	*/

	sid_msgcleanup(ctx);

	/*
	**  Don't fail on the RFC2821 bounce address.
	*/

	if (envfrom[0][0] == '\0' || strcmp(envfrom[0], "<>") == 0)
		return SMFIS_CONTINUE;

	/*
	**  Store the sender information.
	*/

	err = rfc2822_mailbox_split(envfrom[0], &user, &domain);
	if (err == 0 && user != NULL && domain != NULL)
	{
		snprintf(sic->ctx_sender, sizeof sic->ctx_sender,
		         "%s@%s", user, domain);
	}
	else
	{
		return (testmode ? SMFIS_ACCEPT : SMFIS_TEMPFAIL);
	}

	/* if the responsible domain is one we trust, just accept */
	if (domains != NULL)
	{
		int c;

		for (c = 0; domains[c] != NULL; c++)
		{
			if (strcasecmp(domains[c], domain) == 0)
			{
				sid_msgcleanup(ctx);
				return SMFIS_ACCEPT;
			}
		}
	}

	/*
	**  Continue processing.
	*/

	return SMFIS_CONTINUE;
}

/*
**  MLFI_HEADER -- handler for mail headers; stores the header in a vector
**                 of headers for later perusal, removing RFC822 comment
**                 substrings
**
**  Parameters:
**  	ctx -- milter context
**  	headerf -- header
**  	headerv -- value
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	Context sic;
	Header newhdr;

#ifndef DEBUG
	assert(ctx != NULL);
#endif /* !DEBUG */
	assert(headerf != NULL);
	assert(headerv != NULL);

	sic = (Context) smfi_getpriv(ctx);
	assert(sic != NULL);

	newhdr = malloc(sizeof(struct Header));
	if (newhdr == NULL)
	{
		if (dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		sid_msgcleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	newhdr->hdr_hdr = strdup(headerf);
	newhdr->hdr_val = strdup(headerv);
	newhdr->hdr_next = NULL;

	if (newhdr->hdr_hdr == NULL || newhdr->hdr_val == NULL)
	{
		if (dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		TRYFREE(newhdr->hdr_hdr);
		TRYFREE(newhdr->hdr_val);
		sid_msgcleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	if (sic->ctx_hqhead == NULL)
		sic->ctx_hqhead = newhdr;

	if (sic->ctx_hqtail != NULL)
		sic->ctx_hqtail->hdr_next = newhdr;

	sic->ctx_hqtail = newhdr;

	return SMFIS_CONTINUE;
}

/*
**  MLFI_EOH -- handler called when there are no more headers; 
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_eoh(SMFICTX *ctx)
{
	int err;
	char *user;
	char *domain;
	Context sic;
	Header pra;
	char addr[MAXADDRESS + 1];

#ifndef DEBUG
	assert(ctx != NULL);
#endif /* !DEBUG */

	sic = (Context) smfi_getpriv(ctx);
	assert(sic != NULL);

	/*
	**  Determine the message ID for logging.
	*/

	sic->ctx_jobid = smfi_getsymval(ctx, "i");
	if (sic->ctx_jobid == NULL)
	{
		if (no_i_whine && dolog)
		{
			syslog(LOG_WARNING,
			       "WARNING: sendmail symbol 'i' not available");
			no_i_whine = FALSE;
		}
		sic->ctx_jobid = MSGIDUNKNOWN;
	}

	/* find the "purported responsible address" */
	pra = sid_getpra(sic);
	if (pra == NULL)
	{
		if (dolog && !quiet)
		{
			syslog(LOG_ERR,
			       "%s can't determine Purported Responsible Address",
			       sic->ctx_jobid);
		}

		/* XXX -- arrange to add a header maybe? */

		if (nopraok)
		{
			sic->ctx_nopra = TRUE;
		}
		else
		{
			if (!testmode)
			{
				smfi_setreply(ctx, "550", "5.7.1",
				              "can't determine Purported Responsible Address");
			}

			sid_msgcleanup(ctx);
			return (testmode ? SMFIS_ACCEPT : SMFIS_REJECT);
		}
	}

	sic->ctx_pra = pra;

	sm_strlcpy(addr, pra->hdr_val, sizeof addr);
	err = rfc2822_mailbox_split(pra->hdr_val, &user, &domain);
	if (err != 0 || user == NULL || domain == NULL)
	{
		if (dolog && !quiet)
		{
			syslog(LOG_ERR,
			       "%s can't determine responsible domain from `%s'",
			       sic->ctx_jobid, addr);
		}

		/* XXX -- arrange to add a header maybe? */

		if (nopraok)
		{
			sic->ctx_nopra = TRUE;
		}
		else
		{
			if (!testmode)
			{
				char tmp[BUFRSZ + 1];

				snprintf(tmp, sizeof tmp,
				         "can't identify domain in `%s'", addr);
				smfi_setreply(ctx, "550", "5.7.1", tmp);
			}

			sid_msgcleanup(ctx);
			return (testmode ? SMFIS_ACCEPT : SMFIS_REJECT);
		}
	}

	/* short-circuit */
	if (sic->ctx_nopra)
		return SMFIS_CONTINUE;

	/* if the responsible domain is one we trust, just accept */
	if (domains != NULL)
	{
		int c;

		for (c = 0; domains[c] != NULL; c++)
		{
			if (strcasecmp(domains[c], domain) == 0)
			{
				sid_msgcleanup(ctx);
				return SMFIS_ACCEPT;
			}
		}
	}

	sm_strlcpy(sic->ctx_local, user, sizeof sic->ctx_local);
	sm_strlcpy(sic->ctx_domain, domain, sizeof sic->ctx_domain);

	return SMFIS_CONTINUE;
}

/*
**  MLFI_EOM -- handler called at the end of the message
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_eom(SMFICTX *ctx)
{
	bool auth_result;
	sfsistat ret;
	int len;
	int status;
	int sid_result;
	int spf_result;
	int reason;
	Context sic;
	const char *hostname;
        char *auth_type, *auth_author, *auth_ssf, *auth_authen;
	const char *expl;
	char *badaddr;
	char *which;
	char *errmsg;
	char ip[MAXIPADDR + 1];
	char stathdr[MAXHEADER + 1];
	char prahdr[MAXHEADER + 1];
	char pra[MAXADDRESS + 1];
	char sid_errmsg[BUFRSZ + 1];
	char spf_errmsg[BUFRSZ + 1];
	char errout[BUFRSZ + 1];

#ifndef DEBUG
	assert(ctx != NULL);
#endif /* !DEBUG */

	memset(stathdr, '\0', sizeof stathdr);
	memset(spf_errmsg, '\0', sizeof spf_errmsg);
	memset(sid_errmsg, '\0', sizeof sid_errmsg);
	memset(errout, '\0', sizeof errout);

	sic = (Context) smfi_getpriv(ctx);
	assert(sic != NULL);

	/* get hostname; used in the X header and in new MIME boundaries */
	hostname = myname;
	if (hostname == NULL)
		hostname = smfi_getsymval(ctx, "j");
	if (hostname == NULL)
		hostname = HOSTUNKNOWN;

	auth_authen = smfi_getsymval(ctx, "{auth_authen}");
	auth_type = smfi_getsymval(ctx, "{auth_type}");
	auth_ssf = smfi_getsymval(ctx, "{auth_ssf}");
	auth_author = smfi_getsymval(ctx, "{auth_author}");

        auth_result = (auth_authen != NULL && strlen(auth_authen) != 0);

	/* assume we're accepting */
	ret = SMFIS_ACCEPT;

	/* text-ize the IP address */
	memset(ip, '\0', sizeof ip);
	if (sic->ctx_addr.sa_family == AF_INET)
	{
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *) &sic->ctx_addr;
		/* XXX -- not thread-safe!!! (yet) */
		sm_strlcpy(ip, inet_ntoa(sin->sin_addr), sizeof ip);
	}

	/*
	**  Run the Sender-ID query.
	*/

	if (sic->ctx_nopra)
	{
		snprintf(stathdr, sizeof stathdr,
		         "%s; sender-id=neutral (no PRA found)", hostname);

		/* save error message for use in SMTP reply */
		snprintf(sid_errmsg, sizeof sid_errmsg, "no PRA found");

		sid_result = SM_MARID_NEUTRAL;
	}
	else
	{
		expl = NULL;
		snprintf(pra, sizeof pra, "%s@%s", sic->ctx_local,
		         sic->ctx_domain);
		status = sid_marid_check(sic, SM_SCOPE_PRA, ip, pra,
		                         &sid_result, &reason, &expl);
		if (!auth_result && status != 0)
		{
			if (dolog)
			{
				syslog(LOG_ERR,
				       "%s sid_marid_check(): PRA %s: %d (%s)",
				       sic->ctx_jobid, pra, status,
				       sic->ctx_mariderr);
			}

			if (status == -2 && softdns)	/* DNS errors */
			{
				sid_result = SM_MARID_SOFT_FAIL;
				reason = SM_MARID_REASON_NONE;
				if (expl == NULL)
					expl = "DNS failure";
			}
			else
			{
				if (expl == NULL)
					expl = "unknown failure";
				if (smfi_setreply(ctx, "451", "4.7.0",
				                  (char *) expl) != MI_SUCCESS &&
				    dolog)
				{
					syslog(LOG_ERR,
					       "%s smfi_setreply() failed",
					       sic->ctx_jobid);
				}
				sid_msgcleanup(ctx);
				return SMFIS_TEMPFAIL;
			}
		}

		/* construct the status header's content */
		sm_strlcpy(prahdr, sic->ctx_pra->hdr_hdr, sizeof prahdr);
		sid_lowercase(prahdr);
		snprintf(stathdr, sizeof stathdr, "%s; sender-id=", hostname);
		sid_stat_header(sid_result, reason, expl, stathdr,
		                sizeof stathdr);
		len = strlen(stathdr);
		snprintf(stathdr + len, sizeof stathdr - len, " header.%s=%s",
		         prahdr, pra);

		/* save error message for use in SMTP reply */
		sid_stat_header(sid_result, reason, expl, sid_errmsg,
		                sizeof sid_errmsg);
	}

        /*
        **  Log SMTP authentication information, if any.
        */
 
        if (auth_result)
	{
		sm_strlcat(stathdr, "; auth=", sizeof stathdr);
 
		/* positive = pass, 0 = neutral, negative = fail (not used) */

		sm_strlcat(stathdr, auth_result ? "pass" : "fail",
		           sizeof stathdr);
 
		/* plain, cram-md5, etc... */
		if (auth_type != NULL && strlen(auth_type) != 0)
		{
			sm_strlcat(stathdr, " (", sizeof stathdr);
			sm_strlcat(stathdr, auth_type, sizeof stathdr);
			if (auth_ssf != NULL && atoi(auth_ssf) > 1)
			{
				sm_strlcat(stathdr, " ", sizeof stathdr);
				sm_strlcat(stathdr, auth_ssf, sizeof stathdr);
				sm_strlcat(stathdr, " bits", sizeof stathdr);
			}
			sm_strlcat(stathdr, ")", sizeof stathdr);
		}
        }

	/*
	**  Run the "SPF classic" query if the envelope sender wasn't
	**  empty.
	*/

        if (sic->ctx_sender[0] != '\0')
	{
		expl = NULL;
		status = sid_marid_check(sic, SM_SCOPE_SPF, ip,
		                         sic->ctx_sender, &spf_result,
		                         &reason, &expl);
		if (status != 0)
		{
			if (dolog)
			{
				syslog(LOG_ERR,
				       "%s sid_marid_check(): SPF %s: %d (%s)",
				       sic->ctx_jobid, sic->ctx_sender,
				       status, sic->ctx_mariderr);
			}

			if (status == -2 && softdns)		/* DNS errors */
			{
				spf_result = SM_MARID_SOFT_FAIL;
				reason = SM_MARID_REASON_NONE;
				expl = "DNS failure";
			}
			else
			{
				if (expl == NULL)
					expl = "unknown failure";
				if (smfi_setreply(ctx, "451", "4.7.0",
				                  (char *) expl) != MI_SUCCESS &&
				    dolog)
				{
					syslog(LOG_ERR,
					       "%s smfi_setreply() failed",
					       sic->ctx_jobid);
				}
				sid_msgcleanup(ctx);
				return SMFIS_TEMPFAIL;
			}
		}

		sm_strlcat(stathdr, "; spf=", sizeof stathdr);
		sid_stat_header(spf_result, reason, expl, stathdr,
		                sizeof stathdr);
		sm_strlcat(stathdr, " smtp.mfrom=", sizeof stathdr);
		sm_strlcat(stathdr, sic->ctx_sender, sizeof stathdr);

		/* save error message for use in SMTP reply */
		sid_stat_header(sid_result, reason, expl, spf_errmsg,
		                sizeof spf_errmsg);
	}

	/*
	**  Put the status header in place.
	*/

	if (stathdr[0] != '\0' &&
	    smfi_insheader(ctx, 1, AUTHRESULTSHDR, stathdr) != MI_SUCCESS)
	{
		if (dolog)
		{
			syslog(LOG_ERR, "%s smfi_insheader() failed",
			       sic->ctx_jobid);
		}

		sid_msgcleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	/*
	**  Identify the filter, if requested.
	*/

	if (addxhdr)
	{
		char xfhdr[MAXHEADER + 1];

		memset(xfhdr, '\0', sizeof xfhdr);

		snprintf(xfhdr, MAXHEADER, "%s v%s %s %s", SID_PRODUCT,
		         SID_VERSION, hostname,
		         sic->ctx_jobid != NULL ? sic->ctx_jobid
		                                : MSGIDUNKNOWN);

		if (smfi_insheader(ctx, 1, XHEADERNAME, xfhdr) != MI_SUCCESS)
		{
			if (dolog)
			{
				syslog(LOG_ERR, "%s %s() failed",
				       sic->ctx_jobid, ADDHEADERFUNCNAME);
			}

			sid_msgcleanup(ctx);
			return SMFIS_TEMPFAIL;
		}
	}


	sid_msgcleanup(ctx);

	switch (rmode)
	{
	  case 0:					/* accept all */
		ret = SMFIS_ACCEPT;
		break;

	  case 1:					/* need one !FAIL */
		if (sid_result == SM_MARID_FAIL && spf_result == SM_MARID_FAIL)
		{
			badaddr = sic->ctx_sender;
			which = "SPF";
			errmsg = spf_errmsg;
			ret = SMFIS_REJECT;
		}
		break;

	  case 2:					/* need both !FAIL */
		if (sid_result == SM_MARID_FAIL || spf_result == SM_MARID_FAIL)
		{
			if (spf_result == SM_MARID_FAIL)
			{
				badaddr = sic->ctx_sender;
				which = "SPF";
				errmsg = spf_errmsg;
			}
			else
			{
				badaddr = pra;
				which = "Sender-ID";
				errmsg = sid_errmsg;
			}
			ret = SMFIS_REJECT;
		}
		break;

	  case 3:					/* need one PASS */
		if (sid_result != SM_MARID_PASS && spf_result != SM_MARID_PASS)
		{
			badaddr = sic->ctx_sender;
			which = "SPF";
			errmsg = spf_errmsg;
			ret = SMFIS_REJECT;
		}
		break;

	  case 4:					/* need both PASS */
		if (sid_result != SM_MARID_PASS || spf_result != SM_MARID_PASS)
		{
			if (spf_result != SM_MARID_PASS)
			{
				badaddr = sic->ctx_sender;
				which = "SPF";
				errmsg = spf_errmsg;
			}
			else
			{
				badaddr = pra;
				which = "Sender-ID";
				errmsg = sid_errmsg;
			}
			ret = SMFIS_REJECT;
		}
		break;

	  case 5:					/* FAIL without PASS */
		if (sid_result != SM_MARID_PASS &&
		    spf_result != SM_MARID_PASS &&
		    (sid_result == SM_MARID_FAIL ||
		     spf_result == SM_MARID_FAIL))
		{
			if (spf_result == SM_MARID_FAIL)
			{
				badaddr = sic->ctx_sender;
				which = "SPF";
				errmsg = spf_errmsg;
			}
			else
			{
				badaddr = pra;
				which = "Sender-ID";
				errmsg = sid_errmsg;
			}
			ret = SMFIS_REJECT;
		}
		break;
	}

	if (auth_result)
		ret = SMFIS_ACCEPT;

	if (ret == SMFIS_REJECT && !testmode)
	{
		if (rejectmsg == NULL)
		{
			snprintf(errout, sizeof errout,
			         "Rejected due to %s policy for sender %s",
			         which, badaddr);
		}
		else
		{
			int len;
			int n;
			char *p;
			char *q;
			char *end;
			struct sockaddr_in *sin;
			char ip[MAXIPADDR + 1];

			sin = (struct sockaddr_in *) &sic->ctx_addr;
			if (sin->sin_family == AF_INET)
			{
				unsigned char *ab;

				ab = (u_char *) &sin->sin_addr.s_addr;
				snprintf(ip, sizeof ip, "%u.%u.%u.%u",
				         ab[0], ab[1], ab[2], ab[3]);
			}
			else
			{
				sm_strlcpy(ip, "unknown", sizeof ip);
			}

			memset(errout, '\0', sizeof errout);
			q = errout;
			len = sizeof errout;
			end = &errout[0] + len;

			for (p = rejectmsg; *p != '\0'; p++)
			{
				if (*p == '%')
				{
					switch (*(p + 1))
					{
					  case 'a':
						n = sm_strlcat(errout, badaddr,
						               sizeof errout);
						len = sizeof errout - n;
						q = errout + n;
						p++;
						break;
						
					  case 'e':
						n = sm_strlcat(errout, errmsg,
						               sizeof errout);
						len = sizeof errout - n;
						q = errout + n;
						p++;
						break;

					  case 'i':
						n = sm_strlcat(errout, ip,
						               sizeof errout);
						len = sizeof errout - n;
						q = errout + n;
						p++;
						break;

					  case 't':
						n = sm_strlcat(errout, which,
						               sizeof errout);
						len = sizeof errout - n;
						q = errout + n;
						p++;
						break;

					  case '%':
						*q = '%';
						q++;
						len--;
						p++;
						break;

					  default:
						continue;
					}
				}
				else
				{
					*q = *p;
					q++;
					len--;
				}

				if (q >= end)
					break;
			}
		}

#ifdef SMFIF_QUARANTINE
		if (quarantine)
		{
			if (smfi_quarantine(ctx, errout) != MI_SUCCESS)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s smfi_quarantine() failed",
					       sic->ctx_jobid);
				}

				return SMFIS_TEMPFAIL;
			}

			return SMFIS_ACCEPT;
		}
		else
		{
#endif /* SMFIF_QUARANTINE */
			if (smfi_setreply(ctx, "550", "5.7.1",
			                  errout) != MI_SUCCESS && dolog)
			{
				syslog(LOG_ERR, "%s smfi_setreply() failed",
				       sic->ctx_jobid);
			}

			return SMFIS_REJECT;
#ifdef SMFIF_QUARANTINE
		}
#endif /* SMFIF_QUARANTINE */
	}
	else
	{
		return SMFIS_ACCEPT;
	}
}

/*
**  MLFI_CLOSE -- handler called on connection shutdown
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_close(SMFICTX *ctx)
{
	sid_msgcleanup(ctx);
	sid_conncleanup(ctx);
	return SMFIS_CONTINUE;
}

#ifndef DEBUG
/*
**  smfilter -- the milter module description
*/

#ifdef SMFIF_QUARANTINE
# define SID_MILTER_FLAGS	(SMFIF_ADDHDRS|SMFIF_QUARANTINE)
#else /* SMFIF_QUARANTINE */
# define SID_MILTER_FLAGS	(SMFIF_ADDHDRS)
#endif /* SMFIF_QUARANTINE */

struct smfiDesc smfilter =
{
	SID_PRODUCT,	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SID_MILTER_FLAGS, /* flags */
	mlfi_connect,	/* connection info filter */
	NULL,		/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	NULL,		/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	NULL,		/* body block filter */
	mlfi_eom,	/* end of message */
	NULL,		/* message aborted */
	mlfi_close,	/* shutdown */
#if SMFI_VERSION > 2
	NULL,		/* unrecognised command */
#endif
#if SMFI_VERSION > 3
	NULL,		/* DATA */
#endif
#if SMFI_VERSION >= 0x01000000
	mlfi_negotiate,	/* negotiation callback */
#endif
};
#endif /* !DEBUG */

#ifdef DEBUG
int
smfi_addheader(void *ctx, char *hdr, char *val)
{
	printf("smfi_addheader(<ctx>, `%s', `%s')\n", hdr, val);
	return MI_SUCCESS;
}

int
smfi_replacebody(void *ctx, char *p, size_t len)
{
	printf("smfi_replacebody(<ctx>, `%.20s%s', `%d')\n", p,
	       strlen(p) > 20 ? "..." : "", len);
	return MI_SUCCESS;
}

#ifndef NO_SMFI_INSHEADER
int
smfi_insheader(void *ctx, int idx, char *hdr, char *val)
{
	printf("smfi_insheader(<ctx>, %d, `%s', `%s')\n", idx, hdr, val);
	return MI_SUCCESS;
}
#endif /* ! NO_SMFI_INSHEADER */

void
smfi_setconn(char *file)
{
	printf("smfi_setconn(`%s')\n", file);
}

void
smfi_setpriv(void *ctx, void *priv)
{
	fakepriv = priv;
}

void *
smfi_getpriv(void *ctx)
{
	return fakepriv;
}

int
smfi_setreply(void *ctx, char *sc, char *esc, char *reply)
{
	printf("smfi_setreply(<ctx>, `%s', `%s', `%s')\n",
	       sc, esc, reply);
	return MI_SUCCESS;
}

char *
smfi_getsymval(void *ctx, char *sym)
{
	char *ret;
	size_t l;
	Context dfc;

	l = strlen(sym) + 6 + 1;
	dfc = fakepriv;

	printf("smfi_getsymval(<ctx>, `%s')\n", sym);
	ret = malloc(l);
	snprintf(ret, l, "DEBUG-%s", sym);
	return ret;
}

int
smfi_progress(void *ctx)
{
	printf("smfi_progress(<ctx>)\n");

	return MI_SUCCESS;
}

/*
**  SID_DEBUG -- debugging code; simulates libmilter calls
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

int
sid_debug(void)
{
	bool done;
	int status;
	size_t len;
	time_t now;
	char *p;
	char *env[2];
	char data[513];
	char block[4096];
	char tmphdr[4096];

	time(&now);
	srandom(now);

	memset(data, '\0', sizeof data);
	memset(tmphdr, '\0', sizeof tmphdr);

	for (;;)
	{
		if (fgets(data, 512, stdin) == NULL)
			return 1;

		for (p = data; *p != '\0'; p++)
			if (*p == '\r' || *p == '\n')
			{
				*p = '\0';
				break;
			}

		if (strcmp(data, ".") == 0)
			break;

		env[0] = &data[1];
		env[1] = NULL;

		if (data[0] == 'C')
		{
			struct hostent *h;
			struct sockaddr_in sin;

			h = gethostbyname(&data[1]);
			if (h == NULL)
			{
				printf("gethostbyname(\"%s\") failed\n",
				       &data[1]);
				return 1;
			}
			sin.sin_family = AF_INET;
			sin.sin_port = htons(time(NULL) % 65536);
			memcpy(&sin.sin_addr.s_addr, h->h_addr,
			       sizeof sin.sin_addr.s_addr);

			status = mlfi_connect(NULL, &data[1],
			                      (_SOCK_ADDR *) &sin);
			printf("mlfi_connect(NULL, `%s', `%s') returns %s\n",
			       &data[1], inet_ntoa(sin.sin_addr),
			       smfis_ret[status]);
		}
		else if (data[0] == 'F')
		{
			status = mlfi_envfrom(NULL, env);
			printf("mlfi_envfrom(NULL, `%s') returns %s\n", env[0],
	       		       smfis_ret[status]);
		}
/*
		else if (data[0] == 'T')
		{
			status = mlfi_envrcpt(NULL, env);
			printf("mlfi_envrcpt(NULL, `%s') returns %s\n", env[0],
	       		       smfis_ret[status]);
		}
*/
		else
		{
			return 1;
		}

		if (status != SMFIS_CONTINUE)
			return 0;
	}

	for (;;)
	{
		memset(data, '\0', 513);
		if (fgets(data, 512, stdin) == NULL)
			return 1;

		for (p = data; *p != '\0'; p++)
		{
			if (*p == '\r' || *p == '\n')
			{
				*p = '\0';
				break;
			}
		}

		if (strlen(data) > 0 && isascii(data[0]) && isspace(data[0]))
		{
			sm_strlcat(tmphdr, "\r\n", sizeof tmphdr);
			sm_strlcat(tmphdr, data, sizeof tmphdr);
			continue;
		}

		if (strlen(tmphdr) != 0)
		{
			char *q;

			p = strchr(tmphdr, ':');
			*p = '\0';
			for (q = p + 1; isspace(*q); q++)
				continue;
			status = mlfi_header(NULL, tmphdr, q);
			printf("mlfi_header(NULL, `%s', `%s') returns %s\n",
			       tmphdr, q, smfis_ret[status]);
			if (status != SMFIS_CONTINUE)
				return 0;
			memset(tmphdr, '\0', sizeof tmphdr);
		}

		if (strlen(data) == 0)
			break;

		sm_strlcat(tmphdr, data, sizeof tmphdr);
	}

	status = mlfi_eoh(NULL);
	printf("mlfi_eoh(NULL) returns %s\n", smfis_ret[status]);
	if (status != SMFIS_CONTINUE)
		return 0;

	done = FALSE;
	while (!done)
	{
		len = fread(block, 1, 4096, stdin);
#if 0
		status = mlfi_body(NULL, block, len);
		printf("mlfi_body(NULL, <body>, %d) returns %s\n",
		       len, smfis_ret[status]);
		if (status != SMFIS_CONTINUE)
			return 0;
#endif /* 0 */
		if (len < 4096)
			done = TRUE;
	}

	status = mlfi_eom(NULL);
	printf("mlfi_eom(NULL) returns %s\n", smfis_ret[status]);
	return 0;
}
#endif /* DEBUG */

/*
**  USAGE -- print a usage message and return the appropriate exit status
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE.
*/

static int
usage(void)
{
	fprintf(stderr, "%s: usage: %s -p socketfile [options]\n"
	                "-a peerlist\tlist of hosts to ignore\n"
	                "-A         \tauto-restart\n"
	                "-c         \tcontinue on PRA failures\n"
	                "-D         \tsoftfail DNS errors\n"
	                "-d domlist \tdomains to always pass\n"
	                "-f         \tdon't fork-and-exit\n"
	                "-h         \tprepend identifying header\n"
	                "-H name    \thostname to use in headers\n"
	                "-l         \tlog activity to system log\n"
	                "-L level   \tlibmarid log level\n"
	                "-M text    \trejection message\n"
		        "-n         \tdon't use spf1 records for PRA scope\n"
	                "-P pidfile \tfile to which to write pid\n"
	                "-r rmode   \tset rejection mode\n"
#ifdef SMFIF_QUARANTINE
	                "-q         \tquarantine instead of rejecting\n"
#endif /* SMFIF_QUARANTINE */
	                "-Q         \tquiet (less logging)\n"
	                "-t         \ttest-only mode\n"
	                "-T secs    \tDNS timeout\n"
	                "-u userid  \tchange to specified userid\n"
	                "-V         \tprint version number and terminate\n",
	        progname, progname);
	return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Process command line arguments and call the milter mainline.
*/

int
main(int argc, char **argv)
{
	bool autorestart = FALSE;
	bool gotp = FALSE;
	bool dofork = TRUE;
	int c;
#ifndef DEBUG
	int n;
#endif /* ! DEBUG */
	int status;
	const char *args = CMDLINEOPTS;
	FILE *f;
	char *become = NULL;
	char *domlist = NULL;
#ifndef DEBUG
	char *end;
#endif /* ! DEBUG */
	char *p;
	char *pidfile = NULL;
	char *peerfile = NULL;
#ifndef DEBUG
	char argstr[MAXARGV];
#endif /* ! DEBUG */

	/* initialize */
	addxhdr = FALSE;
	softdns = FALSE;
	testmode = FALSE;
	bestguess = FALSE;
	dolog = FALSE;
	nopraspf1 = FALSE;
	nopraok = FALSE;
	quiet = FALSE;
	no_i_whine = TRUE;
	domains = NULL;
	peerlist = NULL;
#if USE_ARLIB
	ar = NULL;
#endif /* USE_ARLIB */
	rmode = 0;
	tmo = DEFTIMEOUT;
	rejectmsg = NULL;
	myname = NULL;

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	/* process command line options */
	while ((c = getopt(argc, argv, args)) != -1)
	{
		switch (c)
		{
		  case 'a':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			peerfile = optarg;
			break;

		  case 'A':
			autorestart = TRUE;
			break;

		  case 'B':
			bestguess = TRUE;
			break;


		  case 'D':
			softdns = TRUE;
			break;

		  case 'd':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			domlist = optarg;
			break;

		  case 'f':
			dofork = FALSE;
			break;

		  case 'h':
			addxhdr = TRUE;
			break;

		  case 'H':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			myname = optarg;
			break;

		  case 'l':
#ifndef DEBUG
			dolog = TRUE;
#endif /* !DEBUG */
			break;

		  case 'L':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			maridlog = strtoul(optarg, &p, 10);
			if (*p != '\0' || maridlog < 0 || maridlog > 8)
			{
				fprintf(stderr,
				        "%s: invalid log level \"%s\"\n",
				        progname, optarg);
				return EX_USAGE;
			}

		  case 'M':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			rejectmsg = optarg;
			break;

		  case 'n':
			nopraspf1 = TRUE ;
			break ;

		  case 'p':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			(void) smfi_setconn(optarg);
			gotp = TRUE;
			break;

		  case 'P':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			pidfile = optarg;
			break;

#ifdef SMFIF_QUARANTINE
		  case 'q':
			quarantine = TRUE;
			break;
#endif /* SMFIF_QUARANTINE */

		  case 'Q':
			quiet = TRUE;
			break;

		  case 'r':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			rmode = strtoul(optarg, &p, 10);
			if (*p != '\0' || rmode < 0 || rmode > 5)
			{
				fprintf(stderr,
				        "%s: invalid rejection mode \"%s\"\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;


		  case 't':
			testmode = TRUE;
			break;

		  case 'T':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			tmo = strtoul(optarg, &p, 10);
			if (*p != '\0')
			{
				fprintf(stderr, "%s: `%s' invalid for -%c\n",
				        progname, optarg, c);
				return EX_USAGE;
			}
			break;

		  case 'u':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			become = optarg;
			break;

		  case 'V':
			printf("%s: %s v%s\n", progname, SID_PRODUCT,
			       SID_VERSION);
			return EX_OK;

		  default:
			return usage();
		}
	}

	if (!gotp)
		return usage();

	if (domlist != NULL)
	{
		int n = 1;

		for (p = domlist; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
		}

		domains = malloc((n + 1) * sizeof(char *));
		if (domains == NULL)
		{
			fprintf(stderr, "%s: malloc(): %s\n",
			        progname, strerror(errno));
			return EX_UNAVAILABLE;
		}

		n = 0;

		for (p = strtok(domlist, ",");
		     p != NULL;
		     p = strtok(NULL, ","))
			domains[n++] = p;

		domains[n] = NULL;
	}

	/* peer list */
	if (peerfile != NULL)
	{
		FILE *f;
		Peer newpeer;
		char peer[MAXHOSTNAMELEN + 1];

		f = fopen(peerfile, "r");
		if (f == NULL)
		{
			fprintf(stderr, "%s: %s: fopen(): %s\n", progname,
			        peerfile, strerror(errno));
			return EX_UNAVAILABLE;
		}

		memset(peer, '\0', sizeof peer);

		while (fgets(peer, sizeof(peer) - 1, f) != NULL)
		{
			for (p = peer; *p != '\0'; p++)
			{
				if (*p == '\n')
				{
					*p = '\0';
					break;
				}
			}

			newpeer = malloc(sizeof(struct Peer));
			if (newpeer == NULL)
			{
				fprintf(stderr, "%s: malloc(): %s\n", progname,
				        strerror(errno));
				return EX_UNAVAILABLE;
			}
			newpeer->peer_next = peerlist;
			peerlist = newpeer;
			p = peer;
			if (*p == '!')
			{
				newpeer->peer_neg = TRUE;
				p++;
			}
			else
			{
				newpeer->peer_neg = FALSE;
			}
			newpeer->peer_info = strdup(p);
			if (newpeer->peer_info == NULL)
			{
				fprintf(stderr, "%s: strdup(): %s\n", progname,
				        strerror(ENOMEM));
				return EX_UNAVAILABLE;
			}
		}
	}

	/* activate logging */
	if (dolog)
	{
#ifdef LOG_MAIL
		openlog(progname, LOG_PID, LOG_MAIL);
#else /* LOG_MAIL */
		openlog(progname, LOG_PID);
#endif /* LOG_MAIL */
	}

	sid_setmaxfd();

	/* change user if appropriate */
	if (become != NULL)
	{
		struct passwd *pw;

		pw = getpwnam(become);
		if (pw == NULL)
		{
			uid_t uid;
			char *q;

			uid = strtoul(become, &q, 10);
			if (*q == '\0')
				pw = getpwuid(uid);
			if (pw == NULL)
			{
				fprintf(stderr, "%s: no such user `%s'\n",
				        progname, become);
				if (dolog)
				{
					syslog(LOG_ERR,
					       "no such user or uid `%s'",
					       become);
				}
				return EX_DATAERR;
			}
		}

		(void) endpwent();

		if (setuid(pw->pw_uid) != 0)
		{
			fprintf(stderr, "%s: setuid(): %s\n", progname,
			        strerror(errno));
			if (dolog)
			{
				syslog(LOG_ERR, "setuid(): %s",
				       strerror(errno));
			}
			return EX_NOPERM;
		}
	}

	die = FALSE;

	if (autorestart)
	{
		bool quitloop = FALSE;
		pid_t pid;
		pid_t wpid;
		struct sigaction sa;

		if (dofork)
		{
			pid = fork();
			switch (pid)
			{
			  case -1:
				if (dolog)
				{
					syslog(LOG_ERR, "fork(): %s",
					       strerror(errno));
				}
				return EX_OSERR;

			  case 0:
				sid_stdio();
				break;

			  default:
				return EX_OK;
			}
		}

		if (pidfile != NULL)
		{
			f = fopen(pidfile, "w");
			if (f != NULL)
			{
				fprintf(f, "%ld\n", (long) getpid());
				(void) fclose(f);
			}
			else
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "can't write pid to %s: %s",
					       pidfile, strerror(errno));
				}
			}
		}

		sa.sa_handler = sid_sighandler;
		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGHUP);
		sigaddset(&sa.sa_mask, SIGINT);
		sigaddset(&sa.sa_mask, SIGTERM);
		sa.sa_flags = 0;

		if (sigaction(SIGHUP, &sa, NULL) != 0 ||
		    sigaction(SIGINT, &sa, NULL) != 0 ||
		    sigaction(SIGTERM, &sa, NULL) != 0)
		{
			if (dolog)
			{
				syslog(LOG_ERR, "[parent] sigaction(): %s",
				       strerror(errno));
			}
		}

		while (!quitloop)
		{
			pid = fork();
			switch (pid)
			{
			  case -1:
				if (dolog)
				{
					syslog(LOG_ERR, "fork(): %s",
					       strerror(errno));
				}
				return EX_OSERR;

			  case 0:
				sa.sa_handler = SIG_DFL;

				if (sigaction(SIGHUP, &sa, NULL) != 0 ||
				    sigaction(SIGINT, &sa, NULL) != 0 ||
				    sigaction(SIGTERM, &sa, NULL) != 0)
				{
					if (dolog)
					{
						syslog(LOG_ERR,
						       "[child] sigaction(): %s",
						       strerror(errno));
					}
				}

				quitloop = TRUE;
				break;

			  default:
				for (;;)
				{
					wpid = wait(&status);

					if (wpid == -1 && errno == EINTR)
					{
						if (die)
						{
							sid_killchild(pid,
							              diesig);

							while (wpid != pid)
								wpid = wait(&status);

							if (pidfile != NULL)
								(void) unlink(pidfile);

							exit(EX_OK);
						}
					}

					if (pid != wpid)
						continue;

					if (wpid != -1 && dolog)
					{
						if (WIFSIGNALED(status))
						{
							syslog(LOG_NOTICE,
							       "terminated with signal %d, restarting",
							       WTERMSIG(status));
						}
						else if (WIFEXITED(status))
						{
							syslog(LOG_NOTICE,
							       "exited with status %d, restarting",
							       WEXITSTATUS(status));
						}
					}

					break;
				}
				break;
			}
		}
	}

#ifndef DEBUG
	/* register with the milter interface */
	if (smfi_register(smfilter) == MI_FAILURE)
	{
		if (dolog)
			syslog(LOG_ERR, "smfi_register() failed");

		fprintf(stderr, "%s: smfi_register() failed\n", progname);

		return EX_UNAVAILABLE;
	}

	/* try to establish the milter socket */
	if (smfi_opensocket(FALSE) == MI_FAILURE)
	{
		if (dolog)
			syslog(LOG_ERR, "smfi_opensocket() failed");

		fprintf(stderr, "%s: smfi_opensocket() failed\n", progname);

		return EX_UNAVAILABLE;
	}
#endif /* !DEBUG */

	if (!autorestart && dofork)
	{
		pid_t pid;

		pid = fork();
		switch(pid)
		{
		  case -1:
			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));
			if (dolog)
				syslog(LOG_ERR, "fork(): %s", strerror(errno));
			return EX_OSERR;

		  case 0:
			sid_stdio();
			break;

		  default:
			return EX_OK;
		}
	}

#if USE_ARLIB
	/* set up the asynchronous resolver */
	ar = ar_init(NULL, NULL, NULL, 0);
	if (ar == NULL)
	{
		if (dolog)
		{
			syslog(LOG_ERR, "can't initialize resolver: %s",
			       strerror(errno));
		}

		return EX_OSERR;
	}
#else /* USE_ARLIB */
	(void) res_init();
#endif /* USE_ARLIB */

	/* write out the pid */
	if (!autorestart && pidfile != NULL)
	{
		f = fopen(pidfile, "w");
		if (f != NULL)
		{
			fprintf(f, "%ld\n", (long) getpid());
			(void) fclose(f);
		}
		else
		{
			if (dolog)
			{
				syslog(LOG_ERR, "can't write pid to %s: %s",
				       pidfile, strerror(errno));
			}
		}
	}

#ifdef DEBUG
	return sid_debug();
#else /* DEBUG */
	memset(argstr, '\0', sizeof argstr);
	end = &argstr[sizeof argstr - 1];
	n = sizeof argstr;
	for (c = 1, p = argstr; c < argc && p < end; c++)
	{
		if (strchr(argv[c], ' ') != NULL)
		{
			status = snprintf(p, n, "%s \"%s\"",
			                  c == 1 ? "args:" : "",
			                  argv[c]);
		}
		else
		{
			status = snprintf(p, n, "%s %s",
			                  c == 1 ? "args:" : "",
			                  argv[c]);
		}

		p += status;
		n -= status;
	}

	if (dolog)
	{
		syslog(LOG_INFO, "%s v%s starting (%s)", SID_PRODUCT,
		       SID_VERSION, argstr);
	}

	/* call the milter mainline */
	errno = 0;
	status = smfi_main();

	if (dolog)
	{
		syslog(LOG_INFO,
		       "%s v%s terminating with status %d, errno = %d",
		       SID_PRODUCT, SID_VERSION, status, errno);
	}

	return status;
#endif /* DEBUG */
}
