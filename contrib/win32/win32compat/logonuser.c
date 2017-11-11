/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Support logon user call on Win32 based operating systems.
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

#include <Windows.h>
#include "debug.h"

static HMODULE hMod = NULL;

/* Define the function prototype */
typedef DWORD(WINAPI *LogonUserExExWType) (wchar_t*, wchar_t*, wchar_t, DWORD, DWORD, PTOKEN_GROUPS, PHANDLE, PSID, PVOID, LPDWORD, PQUOTA_LIMITS);

/*
* The function uses LoadLibrary and GetProcAddress to access
* LogonUserExExW function from onecore.dll o advapi32.dll.
*/
BOOL
LogonUserExExWHelper(wchar_t *user_name, wchar_t *domain, wchar_t *password, DWORD logon_type,
	DWORD logon_provider, PTOKEN_GROUPS token_groups, PHANDLE token, PSID *logon_sid, 
	PVOID *profile_buffer, LPDWORD profile_length, PQUOTA_LIMITS quota_limits)
{
	LogonUserExExWType func = NULL;
	if (hMod == NULL) {
		hMod = LoadLibraryW(L"onecore.dll");
		if (hMod == NULL) {
			hMod = LoadLibraryW(L"advapi32.dll");
		}
	}

	if (hMod)
		func = (LogonUserExExWType)GetProcAddress(hMod, "LogonUserExExW");
	else {
		debug3("Failed to retrieve the module handle of onecore.dll or advapi32.dll");
		return FALSE;
	}

	if (func)
		return func(user_name, domain, password, logon_type, logon_provider,
			token_groups, token, logon_sid, profile_buffer, profile_length, quota_limits);
	else {
		debug3("GetProcAddress(\"LogonUserExExW\") failed.");
		return FALSE;
	}
}