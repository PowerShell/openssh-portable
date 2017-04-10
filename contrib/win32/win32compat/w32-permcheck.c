/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Copyright (c) 2009, 2011 NoMachine
* All rights reserved
*
* Support file permission check functions' replacements needed to let the
* software run on Win32 based operating systems.
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
#include <Sddl.h>
#include <Aclapi.h>

#include "inc\pwd.h"
#include "inc\w32-permcheck.h"
#include "misc_internal.h"
#include "debug.h"

int
w32_secure_file_permission(const char *name, struct passwd * pw, BOOL accept_system_account_as_owner)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
	PSID owner_sid = NULL, user_sid = NULL;
	PACL dacl = NULL;
	int ret = -1;
	BOOL others_have_write_permission = FALSE;

	if (ConvertStringSidToSid(pw->pw_sid, &user_sid) == FALSE ||
		(IsValidSid(user_sid) == FALSE)) {
		debug3("failed to retrieve the sid of the pwd");
		goto cleanup;
	}

	/*Get the owner sid of the file.*/
	if ((ret = GetNamedSecurityInfo(name, SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&owner_sid, NULL, dacl, NULL, &pSD)) != ERROR_SUCCESS ||
		(IsValidSid(owner_sid) == FALSE) ||
		(IsValidAcl(dacl) == FALSE)) {
		debug3("failed to retrieve the owner sid and dacl of file %s with error code: %d", name, ret);
		errno = ENOENT;
		goto cleanup;
	}
	if (!(accept_system_account_as_owner == TRUE && is_system_account(owner_sid)) &&
		(EqualSid(owner_sid, user_sid) == FALSE)) {
		debug3("Bad owner on %s", name);
		ret = 1;
		errno = ENOENT;
		goto cleanup;
	}
	/*
	iterate all aces of the file to find out if others than administrators group,
	system account, and current user account has write permission on the file
	*/
	for (DWORD i = 0; i < dacl->AceCount; i++) {
		PVOID       current_ace = NULL;
		PACE_HEADER current_aceHeader = NULL;
		PSID        current_trustee_sid = NULL;

		if (!GetAce(dacl, i, &current_ace)) {
			debug3("GetAce() failed");
			goto cleanup;
		}

		current_aceHeader = (PACE_HEADER)current_ace;
		// Determine the location of the trustee's sid and the value of the access mask
		switch (current_aceHeader->AceType) {
		case ACCESS_ALLOWED_ACE_TYPE: {
			PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)current_ace;
			current_trustee_sid = &(pAllowedAce->SidStart);
			break;
		}
		case ACCESS_DENIED_ACE_TYPE: {
			PACCESS_DENIED_ACE pDeniedAce = (PACCESS_DENIED_ACE)current_ace;
			current_trustee_sid = &(pDeniedAce->SidStart);			
			break;
		}
		default: {
			// Not interested ACE
			continue;
		}
		}

		/*no need to check administrators group, current user account, and system account*/
		if ( IsWellKnownSid(current_trustee_sid, WinBuiltinAdministratorsSid) ||
			IsWellKnownSid(current_trustee_sid, WinLocalSystemSid) ||
			EqualSid(current_trustee_sid, user_sid)) {
			continue;
		}
		else {
			TRUSTEE trustee = { 0 };
			ACCESS_MASK access_mask = 0;

			BuildTrusteeWithSid(&trustee, current_trustee_sid);
			if (GetEffectiveRightsFromAcl(dacl, &trustee, &access_mask) != ERROR_SUCCESS) {
				debug3("GetEffectiveRightsFromAcl failed.");
				goto cleanup;
			}			

			/*
			Treat SYNCHRONIZE specially by removing it from the Generic Mapping because
			SYNCHRONIZE and READ_CONTROL are always allowed for FILE_GENERIC_READ and FILE_GENERIC_EXECUTE
			*/
			if (access_mask & (FILE_GENERIC_WRITE & ~(SYNCHRONIZE | READ_CONTROL)) != 0) {
				debug3("Bad permission on %s", name);
				ret = 1;
				break;
			}
		}
	}
	if(ret != 1)
		ret = 0;
cleanup:	
	if (pSD)
		LocalFree(pSD);
	if (user_sid)
		FreeSid(user_sid);			
	return ret;
}

BOOL is_system_account(PSID sid)
{
	return IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
		IsWellKnownSid(sid, WinLocalSystemSid);

}