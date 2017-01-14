/*
*
* Copyright (c) 2016 Microsoft Corp.
* All rights reserved
*
* Implementation of following POSIX APIs
* opendir(), readdir(), closedir().
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "inc\utf.h"

#include "inc\dirent.h"
#include "inc\libgen.h"
#include "misc_internal.h"


struct DIR_ {
	intptr_t hFile;
	struct _wfinddata_t c_file;
	int first;
};

/* 
 * Open a directory stream on NAME.
 * Return a DIR stream on the directory, or NULL if it could not be opened.  
 */
DIR* 
opendir(const char *name) {
	struct _wfinddata_t c_file;
	intptr_t hFile;
	DIR *pdir;
	wchar_t searchstr[MAX_PATH];
	wchar_t* wname = NULL;
	int needed;
	
	if ((wname = utf8_to_utf16(sanitized_path(name))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	/* add *.* for Windows _findfirst() search pattern */
	if (swprintf(searchstr, MAX_PATH, L"%s\\*.*", wname) == -1) {
		/* breached MAX_PATH */
		errno = ENOTSUP;
		return NULL;
	}
	free(wname);

	if ((hFile = _wfindfirst(searchstr, &c_file)) == -1) 
		return NULL; /* errno is set by _wfindfirst */

	if ((pdir = malloc(sizeof(DIR))) == NULL) {
		_findclose(hFile);
		errno = ENOMEM;
		return NULL;
	}
			
	memset(pdir, 0, sizeof(DIR));
	pdir->hFile = hFile;
	memcpy(&pdir->c_file, &c_file, sizeof(c_file));
	pdir->first = 1;

	return pdir ;
}

/* 
 * Close the directory stream DIRP.
 * Return 0 if successful, -1 if not.  
 */
int 
closedir(DIR *dirp) {
    if ( dirp && dirp->hFile) {
        _findclose(dirp->hFile);
        dirp->hFile = 0;
        free (dirp);
    }
    return 0;
}

/* Read a directory entry from DIRP. */
struct dirent*
readdir(void *avp) {
	struct dirent *pdirentry = NULL;
	struct _wfinddata_t c_file;
	DIR *dirp = (DIR *)avp;
	char *tmp = NULL;

	for (;;) {
		if (dirp->first) 
			memcpy(&c_file, &dirp->c_file, sizeof(c_file));
		else if (_wfindnext(dirp->hFile, &c_file) != 0)
			return NULL;
		dirp->first = 0;

		/* Skip . and .. */
		if (wcscmp(c_file.name, L".") == 0 || wcscmp(c_file.name, L"..") == 0 )
			continue;
		    
		if ((pdirentry = malloc(sizeof(struct dirent))) == NULL ||
		    (tmp = utf16_to_utf8(c_file.name)) == NULL) {
			if (pdirentry)
				free(pdirentry);
			errno = ENOMEM;
			return NULL;
		}

		strncpy(pdirentry->d_name, tmp, strlen(tmp) + 1);
		free(tmp);

		pdirentry->d_ino = 1; // a fictious one like UNIX to say it is nonzero
		return pdirentry ;
        }
}

// return last part of a path. The last path being a filename.
char *basename(char *path)
{
	char *pdest;

	if (!path)
		return ".";
	pdest = strrchr(path, '/');
	if (pdest)
		return (pdest+1);
	pdest = strrchr(path, '\\');
	if (pdest)
		return (pdest+1);
	
	return path; // path does not have a slash
}
// end of dirent functions in Windows
