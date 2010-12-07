/*
 * Copyright (c) 2000-2001, 2003, 2005 Sendmail, Inc. and its suppliers.
 *      All rights reserved.
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the sendmail distribution.
 */

#include <sm/gen.h>
SM_RCSID("@(#)$Id: shm.c,v 1.19 2005/07/14 22:34:28 ca Exp $")

#if SM_CONF_SHM
# include <stdlib.h>
# include <unistd.h>
# include <errno.h>
# include <sm/string.h>
# include <sm/shm.h>

# ifdef WIN32

#  include <assert.h>
#  include "sm/errstring.h"

/*
**  Some internal non-exposable handles for a memory-mapped file,
**  mapping object and map view object.
*/

static HANDLE hFile = NULL;		/* handle to the map file */
static HANDLE hMapObject = NULL;	/* handle to map object */
static void *pSharedMem = NULL;		/* pointer to the shared memory */
static char shm_pathname[_MAX_PATH];
# endif /* WIN32 */

/*
**  SM_SHMSTART -- initialize shared memory segment.
**
**	Parameters:
**		key -- key for shared memory.
**		size -- size of segment.
**		shmflag -- initial flags.
**		shmid -- pointer to return id.
**		owner -- create segment.
**
**	Returns:
**		pointer to shared memory segment,
**		NULL on failure.
**
**	Side Effects:
**		attaches shared memory segment.
*/

# ifndef WIN32
void *
sm_shmstart(key, size, shmflg, shmid, owner)
	key_t key;
	int size;
	int shmflg;
	int *shmid;
	bool owner;
{
	int save_errno;
	void *shm = SM_SHM_NULL;

	/* default: user/group accessible */
	if (shmflg == 0)
		shmflg = SHM_R|SHM_W|(SHM_R>>3)|(SHM_W>>3);
	if (owner)
		shmflg |= IPC_CREAT|IPC_EXCL;
	*shmid = shmget(key, size, shmflg);
	if (*shmid < 0)
		goto error;

	shm = shmat(*shmid, (void *) 0, 0);
	if (shm == SM_SHM_NULL)
		goto error;

	return shm;

  error:
	save_errno = errno;
	if (shm != SM_SHM_NULL || *shmid >= 0)
		sm_shmstop(shm, *shmid, owner);
	*shmid = SM_SHM_NO_ID;
	errno = save_errno;
	return (void *) 0;
}

# else /* WIN32 */

void *
sm_shmstart(key_t key, int size, int shmflg, int * shmid, BOOL owner)
{
	unsigned long saved_errno;

	(void) sm_snprintf(shm_pathname, sizeof shm_pathname,
			   "%ssendmail_%ld.dat",
			   get_shm_path(), (long) key);

	/* Create or open the shared memory map file */
	hFile = CreateFile(shm_pathname,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			owner ? CREATE_NEW : OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
			0);

	if (hFile == INVALID_HANDLE_VALUE)
		goto error;

	/* Create file mapping */
	hMapObject = CreateFileMapping(hFile, 0, PAGE_READWRITE, 0, size,
				       NULL);

	if (hMapObject == NULL)
		goto error;

	/* Map to process address space */
	pSharedMem = MapViewOfFile(hMapObject, FILE_MAP_ALL_ACCESS, 0, 0,
				   size);
	if (pSharedMem == NULL)
		goto error;

	*shmid = 1;
	return pSharedMem;

error:
	saved_errno = sm_win32_geterror();
	(void) sm_shmstop(pSharedMem, *shmid, owner);
	errno = saved_errno;
	return NULL;
}

# endif /* WIN32 */

/*
**  SM_SHMSTOP -- stop using shared memory segment.
**
**	Parameters:
**		shm -- pointer to shared memory.
**		shmid -- id.
**		owner -- delete segment.
**
**	Returns:
**		0 on success.
**		< 0 on failure.
**
**	Side Effects:
**		detaches (and maybe removes) shared memory segment.
*/

# ifndef WIN32

int
sm_shmstop(shm, shmid, owner)
	void *shm;
	int shmid;
	bool owner;
{
	int r;

	if (shm != SM_SHM_NULL && (r = shmdt(shm)) < 0)
		return r;
	if (owner && shmid >= 0 && (r = shmctl(shmid, IPC_RMID, NULL)) < 0)
		return r;
	return 0;
}

# else /* WIN32 */

int
sm_shmstop(void *shm, int shmid, bool owner)
{
	/* Unmap file view */
	if (shm != NULL && !UnmapViewOfFile(shm))
		goto error;
	if (hMapObject != NULL && !CloseHandle(hMapObject))
		goto error;
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE &&
	    !CloseHandle(hFile))
		goto error;
	if (owner && shmid >= 0)
	{
		assert(strlen(shm_pathname) != 0);
		if (!DeleteFile(shm_pathname))
			goto error;
	}
	return 0;

error:
	errno = sm_win32_geterror();
	return -1;
}

# endif /* WIN32 */

/*
**  SM_SHMSETOWNER -- set owner/group/mode of shared memory segment.
**
**	Parameters:
**		shmid -- id.
**		uid -- uid to use
**		gid -- gid to use
**		mode -- mode to use
**
**	Returns:
**		0 on success.
**		< 0 on failure.
*/

int
sm_shmsetowner(shmid, uid, gid, mode)
	int shmid;
	uid_t uid;
	gid_t gid;
	mode_t mode;
{
# ifndef WIN32
	int r;
	struct shmid_ds shmid_ds;

	memset(&shmid_ds, 0, sizeof(shmid_ds));
	if ((r = shmctl(shmid, IPC_STAT, &shmid_ds)) < 0)
		return r;
	shmid_ds.shm_perm.uid = uid;
	shmid_ds.shm_perm.gid = gid;
	shmid_ds.shm_perm.mode = mode;
	if ((r = shmctl(shmid, IPC_SET, &shmid_ds)) < 0)
		return r;
# endif /* WIN32 */
	return 0;
}
#endif /* SM_CONF_SHM */
