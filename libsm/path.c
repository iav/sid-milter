/*
 * Copyright (c) 2000-2001 Sendmail, Inc. and its suppliers.
 *	All rights reserved.
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the sendmail distribution.
 */

#include <sm/gen.h>
SM_RCSID("@(#)$Id: path.c,v 1.9 2001/09/11 04:04:49 gshapiro Exp $")

#include <sm/path.h>
#include <sm/string.h>

#ifdef WIN32
/*
**  SM_PATH_ISDEVNULL -- Does path specify the null device?
**
**	Parameters:
**		path -- path name.
**
**	Returns:
**		true if a simple string comparison indicates that the
**			specified path names the null device.
**		false otherwise.
*/

bool
sm_path_isdevnull(path)
	const char *path;
{
	size_t len = strlen(path);

	if (len == 3 && sm_strcasecmp(path, "nul") == 0)
		return true;
	else if (len > 3
		 && (path[len - 4] == '/' || path[len - 4] == '\\')
		 && sm_strcasecmp(path + len - 3, "nul") == 0)
		return true;
	return false;
}

/*
**  SM_LAST_DIR_DELIM -- Returns pointer to last directory delimiter.
**
**	Parameters:
**		path -- path name.
**
**	Returns:
**		pointer to last directory delimiter.
**		NULL if path doesn't contain a directory delimiter.
*/

char *
sm_last_dir_delim(path)
	const char *path;
{
	char *p, *n;

	if ((p = strpbrk(path, "/\\")) == NULL)
		return NULL;
	for (;;)
	{
		n = strpbrk(p + 1, "/\\");
		if (n == NULL)
			return p;
		p = n;
	}
}
#endif /* WIN32 */
