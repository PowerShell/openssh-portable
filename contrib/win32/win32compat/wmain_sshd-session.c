/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* wmain entry for sshd-session. 
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
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

/* disable inclusion of compatability defitnitions in CRT headers */
#define __STDC__ 1
#include <Windows.h>
#include <wchar.h>
#include <Lm.h>
#include <sddl.h>
#include <stdio.h>

#include "inc\utf.h"
#include "misc_internal.h"
#include "Debug.h"

int main(int, char **);
extern HANDLE main_thread;

int sshd_session_main(int argc, wchar_t **wargv) {
	char** argv = NULL;
	int i, r;
	_set_invalid_parameter_handler(invalid_parameter_handler);

	if ((argv = malloc((argc + 1) * sizeof(char*))) == NULL)
		fatal("out of memory");

	for (i = 0; i < argc; i++)
		if ((argv[i] = utf16_to_utf8(wargv[i])) == NULL)
			fatal("out of memory");
	argv[argc] = NULL;

	w32posix_initialize();

	r = main(argc, argv);
	w32posix_done();
	return r;
}

int argc_original = 0;
wchar_t **wargv_original = NULL;

int wmain(int argc, wchar_t **wargv) {
	wchar_t *path_value = NULL, *path_new_value;
	errno_t result = 0;
	size_t path_new_len = 0, len;
	argc_original = argc;
	wargv_original = wargv;

	init_prog_paths();
	/* change current directory to sshd-session.exe root */
	_wchdir(__wprogdir);

	/*
	* we want to launch scp and sftp executables from the binary directory
	* that sshd is hosted in. This will facilitate hosting and evaluating
	* multiple versions of OpenSSH at the same time.
	* it does not work well for powershell, cygwin, etc if program path is
	* prepended to executable directory. 
	* To achive above, PATH is set to process environment
	*/
	_wdupenv_s(&path_value, &len, L"PATH");
	if (!path_value || (wcsstr(path_value, __wprogdir)) == NULL) {
		path_new_len = wcslen(__wprogdir) + wcslen(path_value) + 2;
		if ((path_new_value = (wchar_t *) malloc(path_new_len * sizeof(wchar_t))) == NULL) {
			errno = ENOMEM;
			error("failed to allocation memory");
			return -1;
		}
		swprintf_s(path_new_value, path_new_len, L"%s%s%s", __wprogdir, path_value ? L";" : L"",  path_value);
		if (result = _wputenv_s(L"PATH", path_new_value)) {
			error("failed to set PATH environment variable: to value:%s, error:%d", path_new_value, result);
			errno = result;
			if (path_new_value)
				free(path_new_value);
			if(path_value)
				free(path_value);
			return -1;
		}
		if (path_new_value)
			free(path_new_value);
		if(path_value)
			free(path_value);
	}

	return sshd_session_main(argc, wargv);
}
