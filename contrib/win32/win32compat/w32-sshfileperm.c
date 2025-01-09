/*
* Author: Yanbing Wang <yawang@microsoft.com>

* Author: Bryan Berns <berns@uwalumni.com>
*   Updates to account for sidhistory checking
*
* Support file permission check on Win32 based operating systems.
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
#include <lm.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>

#include "inc\pwd.h"
#include "sshfileperm.h"
#include "debug.h"
#include "misc_internal.h"
#include "config.h"

#define NULL_TERMINATOR_LEN		1
#define COMMA_SPACE_LEN			2
#define BACKSLASH_LEN			1

extern int log_on_stderr;

/*
* The function is to check if current user is secure to access to the file. 
* Check the owner of the file is one of these types: Local Administrators groups, system account, current user account
* Check the users have access permission to the file don't voilate the following rules:	
	1. no user other than local administrators group, system account, and pwd user have write permission on the file
* Returns 0 on success and -1 on failure
*/
int
check_secure_file_permission(const char *input_path, struct passwd * pw, int read_ok)
{	
	PSECURITY_DESCRIPTOR pSD = NULL;
	wchar_t * path_utf16 = NULL;
	PSID owner_sid = NULL, user_sid = NULL, ti_sid = NULL;
	PACL dacl = NULL;
	DWORD error_code = ERROR_SUCCESS; 
	BOOL is_valid_sid = FALSE, is_valid_acl = FALSE;
	char *bad_user = NULL;
	int ret = 0;

	if ((user_sid = get_sid(pw ? pw->pw_name : NULL)) == NULL) {
		ret = -1;
		goto cleanup;
	}

	if ((path_utf16 = resolved_path_utf16(input_path)) == NULL) {
		ret = -1;
		goto cleanup;
	}

	ti_sid = get_sid("NT SERVICE\\TrustedInstaller");

	/*Get the owner sid of the file.*/
	if ((error_code = GetNamedSecurityInfoW(path_utf16, SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&owner_sid, NULL, &dacl, NULL, &pSD)) != ERROR_SUCCESS) {
		debug3("failed to retrieve the owner sid and dacl of file %S with error code: %d", path_utf16, error_code);
		errno = EOTHER;
		ret = -1;
		goto cleanup;
	}
	if (((is_valid_sid = IsValidSid(owner_sid)) == FALSE) || ((is_valid_acl = IsValidAcl(dacl)) == FALSE)) {
		debug3("IsValidSid: %d; is_valid_acl: %d", is_valid_sid, is_valid_acl);		
		ret = -1;
		goto cleanup;
	}
	if (!IsWellKnownSid(owner_sid, WinBuiltinAdministratorsSid) &&
	    !IsWellKnownSid(owner_sid, WinLocalSystemSid) &&
	    !EqualSid(owner_sid, user_sid) &&
	    !(ti_sid && EqualSid(owner_sid, ti_sid))) {
		debug3("Bad owner on %S", path_utf16);
		ret = -1;
		goto cleanup;
	}
	/*
	iterate all aces of the file to find out if there is voilation of the following rules:
		1. no others than administrators group, system account, and current user account have write permission on the file
	*/
	for (DWORD i = 0; i < dacl->AceCount; i++) {
		PVOID current_ace = NULL;
		PACE_HEADER current_aceHeader = NULL;
		PSID current_trustee_sid = NULL;
		ACCESS_MASK current_access_mask = 0;		

		if (!GetAce(dacl, i, &current_ace)) {
			debug3("GetAce() failed");
			errno = EOTHER;
			ret = -1;
			goto cleanup;
		}

		current_aceHeader = (PACE_HEADER)current_ace;
		/* only interested in Allow ACE */
		if(current_aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
			continue;
		
		PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)current_ace;
		current_trustee_sid = &(pAllowedAce->SidStart);
		current_access_mask = pAllowedAce->Mask;	
		
		/*no need to check administrators group, pwd user account, and system account*/
		if (IsWellKnownSid(current_trustee_sid, WinBuiltinAdministratorsSid) ||
		    IsWellKnownSid(current_trustee_sid, WinLocalSystemSid) ||
		    EqualSid(current_trustee_sid, user_sid) ||
		    (ti_sid && EqualSid(current_trustee_sid, ti_sid))) {
			continue;
		} else if (read_ok && (current_access_mask & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA)) == 0 ) {
			/* if read is allowed, allow ACES that do not give write access*/
			continue;
		} else {

			/* do reverse lookups on the sids to verify the sids are not actually for 
			 * for the same user as could be the case of a sidhistory entry in the ace */
			wchar_t resolved_user[DNLEN + 1 + UNLEN + 1] = L"UNKNOWN", resolved_trustee[DNLEN + 1 + UNLEN + 1] = L"UNKNOWN";
			DWORD resolved_user_len = _countof(resolved_user), resolved_trustee_len = _countof(resolved_trustee);
			wchar_t resolved_user_domain[DNLEN + 1] = L"UNKNOWN", resolved_trustee_domain[DNLEN + 1] = L"UNKNOWN";
			DWORD resolved_user_domain_len = _countof(resolved_user_domain), resolved_trustee_domain_len = _countof(resolved_trustee_domain);
			SID_NAME_USE resolved_user_type, resolved_trustee_type;
			
			if (LookupAccountSidW(NULL, user_sid, resolved_user, &resolved_user_len,
				resolved_user_domain, &resolved_user_domain_len, &resolved_user_type) != 0 &&
				LookupAccountSidW(NULL, current_trustee_sid, resolved_trustee, &resolved_trustee_len,
					resolved_trustee_domain, &resolved_trustee_domain_len, &resolved_trustee_type) != 0 &&
				wcsicmp(resolved_user, resolved_trustee) == 0 && 
				wcsicmp(resolved_user_domain, resolved_trustee_domain) == 0 &&
				resolved_user_type == resolved_trustee_type) {
				/* same user */
				continue;
			}

			ret = -1;
			if (ConvertSidToStringSid(current_trustee_sid, &bad_user) == FALSE) {
				debug3("ConvertSidToSidString failed with %d. ", GetLastError());
				break;
			}
			logit("Bad permissions. Try removing permissions for user: %S\\%S (%s) on file %S.",
				resolved_trustee_domain, resolved_trustee, bad_user, path_utf16);
			break;
		}
	}	
cleanup:
	if(bad_user)
		LocalFree(bad_user);
	if (pSD)
		LocalFree(pSD);
	if (user_sid)
		free(user_sid);
	if (ti_sid)
		free(ti_sid);
	if(path_utf16)
		free(path_utf16);
	return ret;
}

/*
* The function is similar to check_secure_file_permission.
* Check the owner of the file is one of these types: Local Administrators groups or system account
* Check the users have access permission to the file don't violate the following rules:
	1. no user other than local administrators group and system account have write permission on the folder
* Logs a message if the rules are violated, but does not prevent further execution
*/
void
check_secure_folder_permission(const wchar_t* path_utf16, int read_ok)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
	PSID owner_sid = NULL, ti_sid = NULL;
	PACL dacl = NULL;
	DWORD error_code = ERROR_SUCCESS;
	BOOL is_valid_sid = FALSE, is_valid_acl = FALSE, need_log_msg = FALSE, is_first = TRUE;
	wchar_t* bad_user = NULL;
	size_t log_msg_len = (DNLEN + BACKSLASH_LEN + UNLEN) * 2 + COMMA_SPACE_LEN + NULL_TERMINATOR_LEN;
	wchar_t* log_msg = (wchar_t*)malloc(log_msg_len * sizeof(wchar_t));
	if (log_msg != NULL) {
		log_msg[0] = '\0';
	}

	/*Get the owner sid of the file.*/
	if ((error_code = GetNamedSecurityInfoW(path_utf16, SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&owner_sid, NULL, &dacl, NULL, &pSD)) != ERROR_SUCCESS) {
		printf("failed to retrieve the owner sid and dacl of file %S with error code: %d", path_utf16, error_code);
		errno = EOTHER;
		goto cleanup;
	}
	if (((is_valid_sid = IsValidSid(owner_sid)) == FALSE) || ((is_valid_acl = IsValidAcl(dacl)) == FALSE)) {
		printf("IsValidSid: %d; is_valid_acl: %d", is_valid_sid, is_valid_acl);
		goto cleanup;
	}
	if (!IsWellKnownSid(owner_sid, WinBuiltinAdministratorsSid) &&
		!IsWellKnownSid(owner_sid, WinLocalSystemSid)) {
		printf("Bad owner on %S", path_utf16);
		goto cleanup;
	}
	/*
	iterate all aces of the file to find out if there is violation of the following rules:
		1. no others than administrators group and system account have write permission on the file
	*/
	for (DWORD i = 0; i < dacl->AceCount; i++) {
		PVOID current_ace = NULL;
		PACE_HEADER current_aceHeader = NULL;
		PSID current_trustee_sid = NULL;
		ACCESS_MASK current_access_mask = 0;

		if (!GetAce(dacl, i, &current_ace)) {
			printf("GetAce() failed");
			errno = EOTHER;
			goto cleanup;
		}

		current_aceHeader = (PACE_HEADER)current_ace;
		/* only interested in Allow ACE */
		if (current_aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
			continue;

		PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)current_ace;
		current_trustee_sid = &(pAllowedAce->SidStart);
		current_access_mask = pAllowedAce->Mask;

		/*no need to check administrators group and system account*/
		if (IsWellKnownSid(current_trustee_sid, WinBuiltinAdministratorsSid) ||
			IsWellKnownSid(current_trustee_sid, WinLocalSystemSid)) {
			continue;
		}
		else if (read_ok && (current_access_mask & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA)) == 0) {
			/* if read is allowed, allow ACES that do not give write access*/
			continue;
		}
		else {
			/* collect all SIDs with write permissions */
			wchar_t resolved_trustee[UNLEN + NULL_TERMINATOR_LEN] = L"UNKNOWN";
			wchar_t resolved_trustee_domain[DNLEN + NULL_TERMINATOR_LEN] = L"UNKNOWN";
			DWORD resolved_trustee_len = _countof(resolved_trustee), resolved_trustee_domain_len = _countof(resolved_trustee_domain);
			SID_NAME_USE resolved_trustee_type;

			need_log_msg = TRUE;

			if (log_msg != NULL &&
				LookupAccountSidW(NULL, current_trustee_sid, resolved_trustee, &resolved_trustee_len,
				resolved_trustee_domain, &resolved_trustee_domain_len, &resolved_trustee_type) != 0) {
				if (is_first) {
					_snwprintf_s(log_msg, log_msg_len, _TRUNCATE, L"%ls\\%ls", resolved_trustee_domain, resolved_trustee);
					is_first = FALSE;
				}
				else {
					size_t currentLength = wcslen(log_msg);
					size_t userLength = resolved_trustee_domain_len + BACKSLASH_LEN + resolved_trustee_len + COMMA_SPACE_LEN;
					if (wcslen(log_msg) + userLength + NULL_TERMINATOR_LEN > log_msg_len) {
						log_msg_len *= 2;
						wchar_t* temp_log_msg = (wchar_t*)malloc(log_msg_len * sizeof(wchar_t));
						if (temp_log_msg == NULL) {
							break;
						}
						wcscpy_s(temp_log_msg, log_msg_len, log_msg);
						if (log_msg)
							free(log_msg);
						log_msg = temp_log_msg;
					}
					_snwprintf_s(log_msg + currentLength, log_msg_len - currentLength, _TRUNCATE, 
						L", %ls\\%ls", resolved_trustee_domain, resolved_trustee);
				}
			}
		}
	}

	if (need_log_msg) {
		log_folder_perms_msg_etw(path_utf16, log_msg);
	}
cleanup:
	if (bad_user) {
		LocalFree(bad_user);
	}
	if (log_msg) {
		free(log_msg);
	}
	if (pSD) {
		LocalFree(pSD);
	}
	if (ti_sid) {
		free(ti_sid);
	}
}

/* 
* This function takes in the full path to the ProgramData\ssh folder
* and a string of comma-separated domain\usernames. The function converts 
* the well-known built-in Administrators group sid and the Local System 
* sid to their corresponding names. With these names, and the input string, 
* it logs a message to the Event Viewer. If logging the detailed message fails, 
* a generic log message is written to the Event Viewer instead.
*/
void log_folder_perms_msg_etw(const wchar_t* path_utf16, wchar_t* log_msg) {
	PSID adminSid = NULL;
	WCHAR adminName[UNLEN + NULL_TERMINATOR_LEN];
	WCHAR adminDomain[DNLEN + NULL_TERMINATOR_LEN];
	DWORD adminNameSize = UNLEN + NULL_TERMINATOR_LEN;
	DWORD adminDomainSize = DNLEN + NULL_TERMINATOR_LEN;
	DWORD adminSidSize = SECURITY_MAX_SID_SIZE;
	PSID systemSid = NULL;
	WCHAR systemName[UNLEN + NULL_TERMINATOR_LEN];
	WCHAR systemDomain[DNLEN + NULL_TERMINATOR_LEN];
	DWORD systemNameSize = UNLEN + NULL_TERMINATOR_LEN;
	DWORD systemDomainSize = DNLEN + NULL_TERMINATOR_LEN;
	DWORD systemSidSize = SECURITY_MAX_SID_SIZE;
	SID_NAME_USE sidType;
	BOOL needLog = TRUE;
	int temp_log_on_stderr = log_on_stderr;
	log_on_stderr = 0;

	adminSid = (PSID)malloc(SECURITY_MAX_SID_SIZE);
	if (log_msg != NULL && adminSid != NULL &&
		CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, adminSid, &adminSidSize) != 0 &&
		LookupAccountSidW(NULL, adminSid, adminName, &adminNameSize, adminDomain, &adminDomainSize, &sidType) != 0) {
		systemSid = (PSID)malloc(SECURITY_MAX_SID_SIZE);
		if (systemSid != NULL &&
			CreateWellKnownSid(WinLocalSystemSid, NULL, systemSid, &systemSidSize) != 0 &&
			LookupAccountSidW(NULL, systemSid, systemName, &systemNameSize, systemDomain, &systemDomainSize, &sidType) != 0) {
			logit("For '%S' folder, write access is granted to the following users: %S. "
				"Consider reviewing users to ensure that only %S\\%S, and the %S\\%S group, and its members, have write access.", 
				path_utf16, log_msg, systemDomain, systemName, adminDomain, adminName);
			needLog = FALSE;
		}
	}

	if (needLog) {
		/* log generic warning message in unlikely case that lookup for either well-known SID fails or user list is empty */
		logit("for '%S' folder, consider downgrading permissions for any users with unnecessary write access.", path_utf16);
	}

	log_on_stderr = temp_log_on_stderr;

	if (adminSid) {
		free(adminSid);
	}
	if (systemSid) {
		free(systemSid);
	}
}
