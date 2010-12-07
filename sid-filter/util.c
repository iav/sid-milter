/*
**  Copyright (c) 2004, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**  Sendmail, Inc. Confidential
**
**  $Id: util.c,v 1.11 2008/05/27 16:36:47 msk Exp $
*/

#ifndef lint
static char util_c_id[] = "@(#)$Id: util.c,v 1.11 2008/05/27 16:36:47 msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

/* libsm includes */
#include <sm/string.h>

/* sid-filter includes */
#include "sid-filter.h"
#include "util.h"

/*
**  SID_SETMAXFD -- increase the file descriptor limit as much as possible
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
sid_setmaxfd(void)
{
	struct rlimit rlp;

	if (getrlimit(RLIMIT_NOFILE, &rlp) != 0)
	{
		syslog(LOG_WARNING, "getrlimit(): %s", strerror(errno));
	}
	else
	{
		rlp.rlim_cur = rlp.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rlp) != 0)
		{
			syslog(LOG_WARNING, "setrlimit(): %s",
			       strerror(errno));
		}
	}
}

/*
**  SID_STRIPBRACKETS -- remove angle brackets from the sender address
**
**  Parameters:
** 	addr -- address to be processed
**
**  Return value:
**  	None.
*/

void
sid_stripbrackets(char *addr)
{
	char *p, *q;

	assert(addr != NULL);

	p = addr;
	q = addr + strlen(addr) - 1;

	while (*p == '<' && *q == '>')
	{
		p++;
		*q-- = '\0';
	}

	if (p != addr)
	{
		for (q = addr; *p != '\0'; p++, q++)
			*q = *p;
		*q = '\0';
	}
}

/*
**  SID_LOWERCASE -- lowercase-ize a string
**
**  Parameters:
**  	str -- string to convert
**
**  Return value:
**  	None.
*/

void
sid_lowercase(char *str)
{
	char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (isascii(*p) && isupper(*p))
			*p = tolower(*p);
	}
}

/*
**  SID_INET_NTOA -- thread-safe inet_ntoa()
**
**  Parameters:
**  	a -- (struct in_addr) to be converted
**  	buf -- destination buffer
**  	buflen -- number of bytes at buf
**
**  Return value:
**  	Size of the resultant string.  If the result is greater than buflen,
**  	then buf does not contain the complete result.
*/

size_t
sid_inet_ntoa(struct in_addr a, char *buf, size_t buflen)
{
	in_addr_t addr;

	assert(buf != NULL);

	addr = ntohl(a.s_addr);

	return snprintf(buf, buflen, "%d.%d.%d.%d",
	                (addr >> 24), (addr >> 16) & 0xff,
	                (addr >> 8) & 0xff, addr & 0xff);
}

/*
**  SID_LIST_LOOKUP -- look up a name in a peerlist
**
**  Parameters:
**  	list -- list of records to check
** 	data -- record to find
**
**  Return value:
**   	TRUE if found, FALSE otherwise
*/

static bool
sid_list_lookup(Peer list, char *data)
{
	bool out = FALSE;
	Peer current;

	assert(list != NULL);
	assert(data != NULL);

	for (current = list; current != NULL; current = current->peer_next)
	{
		if (strcasecmp(data, current->peer_info) == 0)
			out = current->peer_neg;
	}

	return out;
}

/*
**  SID_CHECKHOST -- check the peerlist for a host and its wildcards
**
**  Parameters:
**  	list -- list of records to check
**  	host -- hostname to find
**
**  Return value:
**  	None.
*/

bool
sid_checkhost(Peer list, char *host)
{
	char *p;

	assert(list != NULL);
	assert(host != NULL);

	if (sid_list_lookup(list, host))
		return TRUE;

	for (p = strchr(host, '.');
	     p != NULL;
	     p = strchr(p + 1, '.'))
	{
		if (sid_list_lookup(list, p))
			return TRUE;
	}

	return FALSE;
}

/*
**  SID_CHECKIP -- check a peerlist table for an IP address or its matching
**                 wildcards
**
**  Parameters:
**  	list -- list to check
**  	ip -- IP address to find
**
**  Return value:
**  	None.
*/

bool
sid_checkip(Peer list, struct sockaddr *ip)
{
	bool out = FALSE;
	char ipbuf[MAXHOSTNAMELEN + 1];

	assert(ip != NULL);

	/* short circuit */
	if (list == NULL)
		return FALSE;

#if NETINET6
	if (ip->sa_family == AF_INET6)
	{
		struct sockaddr_in6 sin6;
		struct in6_addr addr;

		memcpy(&sin6, ip, sizeof sin6);

		memcpy(&addr, &sin6.sin6_addr, sizeof addr);

		if (IN6_IS_ADDR_V4MAPPED(&addr))
		{
			inet_ntop(AF_INET,
			          &addr.s6_addr[INET6_ADDRSTRLEN - INET_ADDRSTRLEN],
			          ipbuf, sizeof ipbuf);
		}
		else
		{
			char *dst;
			size_t sz;
			size_t dst_len;

			dst = ipbuf;
			dst_len = sizeof ipbuf;

			memset(ipbuf, '\0', sizeof ipbuf);

			sz = sm_strlcpy(ipbuf, "IPv6:", sizeof ipbuf);
			if (sz >= sizeof ipbuf)
				return FALSE;

			dst += sz;
			dst_len -= sz;
			inet_ntop(AF_INET6, &addr, dst, dst_len);
		}

		return (sid_list_lookup(list, ipbuf));
	}
#endif /* NETINET6 */

	if (ip->sa_family == AF_INET)
	{
		int bits;
		char *p;
		char *q;
		struct Peer *node;
		struct in_addr addr;
		struct in_addr mask;
		struct in_addr compare;
		struct sockaddr_in sin;

		memcpy(&sin, ip, sizeof sin);

		memcpy(&addr.s_addr, &sin.sin_addr, sizeof addr.s_addr);

		/* walk the list */
		for (node = list; node != NULL; node = node->peer_next)
		{
			/* try the IP direct match */
			(void) sid_inet_ntoa(addr, ipbuf, sizeof ipbuf);
			if (strcmp(ipbuf, node->peer_info) == 0)
			{
				out = !node->peer_neg;
				continue;
			}

			/* try the IP/CIDR and IP/mask possibilities */
			p = strchr(node->peer_info, '/');
			if (p == NULL)
				continue;

			*p = '\0';
			compare.s_addr = inet_addr(node->peer_info);
			if (compare.s_addr == INADDR_NONE)
			{
				*p = '/';
				continue;
			}

			bits = strtoul(p + 1, &q, 10);

			if (*q == '.')
			{
				mask.s_addr = inet_addr(p + 1);
				if (mask.s_addr == INADDR_NONE)
				{
					*p = '/';
					continue;
				}
			}
			else if (*q != '\0')
			{
				*p = '/';
				continue;
			}
			else
			{
				int c;

				mask.s_addr = 0;
				for (c = 0; c < bits; c++)
					mask.s_addr |= htonl(1 << (31 - c));
			}

			if ((addr.s_addr & mask.s_addr) == (compare.s_addr & mask.s_addr))
				out = !node->peer_neg;

			*p = '/';
		}
	}

	return out;
}
