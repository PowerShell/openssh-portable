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
#include <Ntsecapi.h>
#include <lm.h>

#include "inc\pwd.h"
#include "inc\w32-permcheck.h"
#include "misc_internal.h"
#include "debug.h"

#define SSHD_ACCOUNT L"NT Service\\sshd"

/*
	* Returns 0 on valid file permission
	* Returns 1 on invalid file permission
	* Return -1 on internal failures
*/
int
w32_secure_file_permission(const char *name, struct passwd * pw)
{
	char buf[PATH_MAX], homedir[PATH_MAX];
	BOOL file_in_home_dir = FALSE;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PSID owner_sid = NULL, user_sid = NULL;
	PACL dacl = NULL;
	int ret = -1;
	BOOL others_have_write_permission = FALSE;
	char * cp;

	if (pw == NULL) {
		debug3("invalid parameter pw is null");
		return -1;
	}	
	if (ConvertStringSidToSid(pw->pw_sid, &user_sid) == FALSE ||
		(IsValidSid(user_sid) == FALSE)) {
		debug3("failed to retrieve the sid of the pwd");
		goto cleanup;
	}

	/*Get the owner sid of the file.*/
	if ((ret = GetNamedSecurityInfo(name, SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&owner_sid, NULL, &dacl, NULL, &pSD)) != ERROR_SUCCESS ||
		(IsValidSid(owner_sid) == FALSE) ||
		(IsValidAcl(dacl) == FALSE)) {
		debug3("failed to retrieve the owner sid and dacl of file %s with error code: %d", name, ret);
		errno = ENOENT;
		goto cleanup;
	}
	if ((IsWellKnownSid(owner_sid, WinBuiltinAdministratorsSid) == FALSE) &&
		(IsWellKnownSid(owner_sid, WinLocalSystemSid) == FALSE) &&
		(EqualSid(owner_sid, user_sid) == FALSE) &&
		(is_admin_user(owner_sid) == FALSE)) {
		debug3("Bad owner on %s", name);
		ret = 1;
		errno = ENOENT;
		goto cleanup;
	}
	/*
	iterate all aces of the file to find out if there is voilation of the following rules:
		1. no others than administrators group, system account, and current user, owner accounts have write permission on the file
		2. sshd account can only have read permission
		3. current user and file owner should at least have read permission 
	*/
	for (DWORD i = 0; i < dacl->AceCount; i++) {
		PVOID current_ace = NULL;
		PACE_HEADER current_aceHeader = NULL;
		PSID current_trustee_sid = NULL;
		ACCESS_MASK current_access_mask = 0;		

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
			current_access_mask = pAllowedAce->Mask;
			break;
		}
		case ACCESS_DENIED_ACE_TYPE: {
			PACCESS_DENIED_ACE pDeniedAce = (PACCESS_DENIED_ACE)current_ace;
			current_trustee_sid = &(pDeniedAce->SidStart);			
			if (EqualSid(current_trustee_sid, owner_sid) || EqualSid(current_trustee_sid, user_sid)
				&& (pDeniedAce->Mask & (FILE_GENERIC_READ & ~(SYNCHRONIZE | READ_CONTROL))) != 0) {
				debug3("Bad permission on %s", name);
				ret = 1;
				goto cleanup;
			}
			continue;
		}
		default: {
			// Not interested ACE
			continue;
		}
		}
		
		/*no need to check administrators group, owner account, user account and system account*/
		if ((IsWellKnownSid(current_trustee_sid, WinBuiltinAdministratorsSid) ||
			IsWellKnownSid(current_trustee_sid, WinLocalSystemSid) ||
			EqualSid(current_trustee_sid, owner_sid) ||
			EqualSid(current_trustee_sid, user_sid) ||
			is_admin_user(current_trustee_sid))) {
			continue;
		}
		else if(is_sshd_account(current_trustee_sid)){
			if ((current_access_mask & ~FILE_GENERIC_READ) != 0){
				debug3("Bad permission on %s", name);
				ret = 1;
				break;			
			}			
		}
		else {
			debug3("Bad permission on %s", name);
			ret = 1;
			break;
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

BOOL
is_sshd_account(PSID user_sid){
	wchar_t * full_name = NULL;
	BOOL ret = FALSE;
	if (sid_to_user(user_sid, &full_name) != 0) {
		debug3("sid_to_user failed.");
		goto done;
	}

	ret = (wcsicmp(full_name, SSHD_ACCOUNT) == 0);
done:
	if(full_name)
		free(full_name);
	
}

/* Check if the user is in administrators group*/
BOOL
is_admin_user(PSID user_sid)
{
	DWORD entries_read = 0, total_entries = 0, i = 0;
	wchar_t * full_name = NULL;
	LPLOCALGROUP_USERS_INFO_0 local_groups_info = NULL, tmp_groups_info;
	NET_API_STATUS status;
	BOOL ret = FALSE;

	if (sid_to_user(user_sid, &full_name) != 0) {
		debug3("sid_to_user() failed");
		goto done;
	}
	status = NetUserGetLocalGroups(NULL, full_name, 0, LG_INCLUDE_INDIRECT, (LPBYTE *)&local_groups_info,
		MAX_PREFERRED_LENGTH, &entries_read, &total_entries);
	if (NERR_Success != status) {
		debug3("NetUserGetLocalGroups() failed with error: %u on user %S", status, full_name);
		goto done;
	}

	if (entries_read != total_entries) {
		debug3("NetUserGetLocalGroups(): entries_read (%u) is not equal to "
			"total_entries (%u)", entries_read, total_entries);
		goto done;
	}

	if ((tmp_groups_info = local_groups_info) != NULL) {
		for (i = 0; i < total_entries; i++) {
			if (is_well_known_account_name(tmp_groups_info->lgrui0_name, WinBuiltinAdministratorsSid)) {
				ret = TRUE;
				break;
			}
			tmp_groups_info++;
		}
	}

done:
	if (local_groups_info)
		NetApiBufferFree(local_groups_info);
	if(full_name)
		free(full_name);
	return ret;
}

/* Check if the account name is wellknown account on windows*/
BOOL
is_well_known_account_name(LPWSTR account_name, WELL_KNOWN_SID_TYPE well_know_sid_type)
{
	PSID user_sid = NULL;
	BOOL ret = FALSE;

	if (user_to_sid(account_name, &user_sid) != 0) {
		debug3("user_to_sid failed.");
		errno = ENOENT;
		goto done;

	}
	ret = IsWellKnownSid(user_sid, well_know_sid_type);
done:

	if (user_sid)
		free(user_sid);
	return ret;
}

int
sid_to_user(PSID user_sid, wchar_t ** full_name)
{	
	char *user_utf8, *udom_utf8;
	wchar_t *user_utf16 = NULL, *udom_utf16 = NULL, *full_name_utf16 = NULL;
	DWORD domain_name_length = 0, name_length = 0, full_name_len = 0;
	SID_NAME_USE sid_type = SidTypeInvalid;
	int ret = -1;
	if (LookupAccountSidLocal(user_sid, NULL, &name_length, NULL, &domain_name_length, &sid_type))
	{		
		debug3("LookupAccountSidLocal() succeed unexpectedly. ");
		errno = ENOENT;	
		return NULL;
	}

	if (((user_utf8 = (char *)malloc(name_length + 1)) == NULL) ||
		((udom_utf8 = (char *) malloc(domain_name_length + 1)) == NULL)) {
		debug3("Insufficient memory available");
		errno = ENOMEM;
		goto done;
	}

	if (LookupAccountSidLocal(user_sid, user_utf8, &name_length, udom_utf8, &domain_name_length, &sid_type) == FALSE)
	{
		debug3("LookupAccountSidLocal() failed with error: %d. ", GetLastError());
		errno = ENOENT;
		goto done;
	}

	if (((user_utf16 = utf8_to_utf16(user_utf8)) == NULL) ||
		((udom_utf16 = utf8_to_utf16(udom_utf8)) == NULL)) {		
		errno = ENOMEM;
		goto done;
	}

	full_name_len = ((wcslen(user_utf16)+ wcslen(udom_utf16) + 2) * sizeof(wchar_t));
	if ((*full_name = full_name_utf16 = (wchar_t *) malloc(full_name_len)) == NULL) {
		errno = ENOMEM;
		goto done;
	}	

	wmemcpy(full_name_utf16, udom_utf16, wcslen(udom_utf16)+1);
	full_name_utf16[wcslen(udom_utf16)] = L'\\';
	wmemcpy(full_name_utf16 + wcslen(udom_utf16) + 1, user_utf16, wcslen(user_utf16));
	full_name_utf16[wcslen(udom_utf16)+ wcslen(user_utf16)+1] = L'\0';
	ret = 0;
done:	
	if (user_utf16)
		free(user_utf16);	
	if (udom_utf16)
		free(udom_utf16);
	if (user_utf8)
		free(user_utf8);
	if (udom_utf8)
		free(udom_utf8);
	return ret;	
}

int
user_to_sid(const LPWSTR account_name, PSID * sid)
{
	DWORD user_sid_size = 0, domain_size = 0;
	SID_NAME_USE sid_type = SidTypeInvalid;
	PSID user_sid = NULL;
	wchar_t* domain_name = NULL;
	int ret = -1;
	
	if (LookupAccountNameW(NULL, account_name, NULL, &user_sid_size, 
		NULL, &domain_size, &sid_type)) {
		debug3("LookupAccountNameW() succeeded unexpectedly.");
		errno = ENOENT;
		goto done;
	}

	if ((*sid = user_sid = (SID *)malloc(user_sid_size )) == NULL ||
		(domain_size > 0 && (((wchar_t*)domain_name = malloc(domain_size * sizeof(wchar_t))) == NULL))) {
		debug3("Insufficient memory available");
		errno = ENOMEM;
		goto done;
	}

	if (LookupAccountNameW(NULL, account_name, user_sid, &user_sid_size,
		domain_name, &domain_size, &sid_type) == FALSE) {
		debug3("LookupAccountNameW() failed. Error code is : %d.", GetLastError());
		errno = ENOENT;
		goto done;
	}
	if (!IsValidSid(user_sid)) {
		debug3("the sid is invalid.");
		errno = ENOENT;
		goto done;
	}
	ret = 0;
done:
	if (domain_name)
		free(domain_name);
	return ret;
}