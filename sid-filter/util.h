/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**  Sendmail, Inc. Confidential
**
**  $Id: util.h,v 1.3 2004/06/18 21:28:01 msk Exp $
*/

#ifndef _UTIL_H_
#define _UTIL_H_

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>

/* libsm includes */
#include <sm/gen.h>

#ifndef lint
static char util_h_id[] = "@(#)$Id: util.h,v 1.3 2004/06/18 21:28:01 msk Exp $";
#endif /* !lint */

/* PROTOTYPES */
extern bool sid_checkhost(Peer list, char *host);
extern bool sid_checkip(Peer list, struct sockaddr *ip);
extern void sid_extract_address(char *hdr, char *buf, size_t buflen);
extern void sid_lowercase(char *str);
extern void sid_setmaxfd(void);
extern void sid_stripbrackets(char *addr);

#endif /* _UTIL_H_ */
