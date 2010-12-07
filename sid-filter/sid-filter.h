/*
**  Copyright (c) 2004-2006, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**  Sendmail, Inc. Confidential
**
**  $Id: sid-filter.h,v 1.64 2008/06/07 21:09:26 msk Exp $
*/

#ifndef _SID_FILTER_H_
#define _SID_FILTER_H_

#ifndef lint
static char sid_filter_h_id[] = "@(#)$Id: sid-filter.h,v 1.64 2008/06/07 21:09:26 msk Exp $";
#endif /* !lint */

#include <sys/param.h>

#define	SID_PRODUCT	"Sendmail Sender-ID Filter"
#define	SID_VERSION	"1.0.0"

/* make sure we have TRUE and FALSE */
#ifndef FALSE
# define FALSE		0
#endif /* !FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* !TRUE */

/* and some other things */
#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN	256
#endif /* ! MAXHOSTNAMELEN */

#ifndef MAX
# define MAX(x,y)	((x) > (y) ? (x) : (y))
#endif /* ! MAX */

/* defaults, limits, etc. */
#define	BUFRSZ		256
#define	CMDLINEOPTS	"a:ABcC:d:DfhH:lL:M:np:P:qQr:R:tT:u:V"
#define	DEFTIMEOUT	5
#define	INADDRDOMAIN	"in-addr.arpa"
#define	MARIDREPLIES	32
#define	MARIDREPLYSZ	512
#define	MAXADDRESS	256
#define	MAXARGV		65536
#define	MAXCNAMEDEPTH	3
#define	MAXHEADER	1024
#define	MAXDEPTH	20
#define	MAXIPADDR	15
#define MAXMXSETSZ	16
#define	MAXPACKET	8192
#define	HOSTUNKNOWN	"unknown-host"
#define	MSGIDUNKNOWN	"<unknown-msgid>"
#define	REPLYWAIT	3
#define	XHEADERNAME	"X-SenderID"
#define	AUTHRESULTSHDR	"Authentication-Results"

#define	FROMHDR		"From"
#define	RECEIVEDHDR	"Received"
#define	RESENTFROMHDR	"Resent-From"
#define	RESENTSENDERHDR	"Resent-Sender"
#define	RETURNPATHHDR	"Return-Path"
#define	SENDERHDR	"Sender"

/*
**  PEER -- peer list, listing clients to ignore
*/

typedef struct Peer * Peer;
struct Peer
{
	bool		peer_neg;
	char *		peer_info;
	struct Peer *	peer_next;
};

/*
**  LOOKUP -- lookup table
*/

struct Lookup
{
	char *		table_str;
	int		table_int;
};

#endif /* _SID_FILTER_H_ */
