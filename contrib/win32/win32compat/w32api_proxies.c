/*
* Author: Yanbing Wang <yawang@microsoft.com>
*	Support logon user call on Win32 based operating systems.
*
* Author: Manoj Ampalam <manojamp@microsoft.com>
*	Added generalized wrappers for run time dll loading
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

#include "w32api_proxies.h"
#include "debug.h"

static wchar_t* 
system32_dir()
{
	static wchar_t* s_system32_dir = NULL;
	static wchar_t s_system32_path[MAX_PATH + 1] = { 0, };

	if (s_system32_dir)
		return s_system32_dir;

	if (!GetSystemDirectoryW(s_system32_path, _countof(s_system32_path))) {
		debug3("GetSystemDirectory failed with error %d", GetLastError());
		return NULL;
	}
	s_system32_dir = s_system32_path;

	return s_system32_dir;
}

static HMODULE 
load_module(wchar_t* name)
{
	wchar_t module_path[MAX_PATH + 1];
	wchar_t *system32_path;
	HMODULE hm = NULL;
	
	if ((system32_path = system32_dir()) == NULL)
		return NULL;

	module_path[0] = L'\0';
	if (wcscat_s(module_path, _countof(module_path), system32_path) != 0 ||
	    wcscat_s(module_path, _countof(module_path), L"\\") != 0 ||
	    wcscat_s(module_path, _countof(module_path), name) != 0)
		return NULL;

	if ((hm = LoadLibraryW(module_path)) == NULL)
		debug3("unable to load module %ls at run time, error: %d", name, GetLastError());

	return hm;
}

static HMODULE
load_sspicli()
{
	static HMODULE s_hm_sspicli = NULL;

	if (!s_hm_sspicli)
		s_hm_sspicli = load_module(L"sspicli.dll");

	return s_hm_sspicli;
}

static HMODULE
load_advapi32()
{
	static HMODULE s_hm_advapi32 = NULL;

	if (!s_hm_advapi32)
		s_hm_advapi32 = load_module(L"advapi32.dll");

	return s_hm_advapi32;
}

static HMODULE
load_api_security_lsapolicy()
{
	static HMODULE s_hm_api_security_lsapolicy = NULL;

	if (!s_hm_api_security_lsapolicy)
		s_hm_api_security_lsapolicy = load_module(L"downlevel\\api-ms-win-security-lsapolicy-l1-1-0.dll");

	return s_hm_api_security_lsapolicy;
}

static HMODULE
load_secur32()
{
	static HMODULE s_hm_secur32 = NULL;

	if (!s_hm_secur32)
		s_hm_secur32 = load_module(L"secur32.dll");

	return s_hm_secur32;
}

static HMODULE
load_ntdll()
{
	static HMODULE s_hm_ntdll = NULL;

	if (!s_hm_ntdll)
		s_hm_ntdll = load_module(L"ntdll.dll");

	return s_hm_ntdll;
}

FARPROC get_proc_address(HMODULE hm, char* fn)
{
	FARPROC ret = GetProcAddress(hm, fn);
	if (!ret)
		debug3("GetProcAddress of %s failed with error $d.", fn, GetLastError());

	return ret;
}

BOOL
pLogonUserExExW(wchar_t *user_name, wchar_t *domain, wchar_t *password, DWORD logon_type,
	DWORD logon_provider, PTOKEN_GROUPS token_groups, PHANDLE token, PSID *logon_sid, 
	PVOID *profile_buffer, LPDWORD profile_length, PQUOTA_LIMITS quota_limits)
{
	HMODULE hm;
	typedef BOOL(WINAPI *LogonUserExExWType)(wchar_t*, wchar_t*, wchar_t*, DWORD, DWORD, PTOKEN_GROUPS, PHANDLE, PSID, PVOID, LPDWORD, PQUOTA_LIMITS);
	static LogonUserExExWType s_pLogonUserExExW = NULL;

	if (!s_pLogonUserExExW) {
		/* this API is typically found in sspicli, but this dll doesn't exist on some downlevel machines - we fallback to advapi32 then */
		if ((hm = load_sspicli()) == NULL &&
		    (hm = load_advapi32()) == NULL)
			return FALSE;

		if ((s_pLogonUserExExW = (LogonUserExExWType)get_proc_address(hm, "LogonUserExExW")) == NULL)
			return FALSE;
	}
	
	return s_pLogonUserExExW(user_name, domain, password, logon_type, logon_provider,
			token_groups, token, logon_sid, profile_buffer, profile_length, quota_limits);	
}


BOOLEAN pTranslateNameW(LPCWSTR name,
	EXTENDED_NAME_FORMAT account_format,
	EXTENDED_NAME_FORMAT desired_name_format,
	LPWSTR translated_name,
	PULONG psize)
{
	HMODULE hm;
	typedef BOOLEAN(WINAPI *TranslateNameWType)(LPCWSTR, EXTENDED_NAME_FORMAT, EXTENDED_NAME_FORMAT, LPWSTR, PULONG);
	static TranslateNameWType s_pTranslateNameW = NULL;

	if (!s_pTranslateNameW) {
		if ((hm = load_secur32()) == NULL)
			return FALSE;

		if ((s_pTranslateNameW = (TranslateNameWType)get_proc_address(hm, "TranslateNameW")) == NULL)
			return FALSE;
	}

	return s_pTranslateNameW(name, account_format, desired_name_format, translated_name, psize);
}

NTSTATUS pLsaOpenPolicy(PLSA_UNICODE_STRING system_name,
	PLSA_OBJECT_ATTRIBUTES attrib,
	ACCESS_MASK access,
	PLSA_HANDLE handle)
{
	HMODULE hm;
	typedef NTSTATUS(*LsaOpenPolicyType)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	static LsaOpenPolicyType s_pLsaOpenPolicy = NULL;

	if (!s_pLsaOpenPolicy) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
				return STATUS_ASSERTION_FAILURE;

		if ((s_pLsaOpenPolicy = (LsaOpenPolicyType)get_proc_address(hm, "LsaOpenPolicy")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}

	return s_pLsaOpenPolicy(system_name, attrib, access, handle);
}

NTSTATUS pLsaFreeMemory(PVOID buffer)
{
	HMODULE hm;
	typedef NTSTATUS(*LsaFreeMemoryType)(PVOID);
	static LsaFreeMemoryType s_pLsaFreeMemory = NULL;

	if (!s_pLsaFreeMemory) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
			return STATUS_ASSERTION_FAILURE;

		if ((s_pLsaFreeMemory = (LsaFreeMemoryType)get_proc_address(hm, "LsaFreeMemory")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}

	return s_pLsaFreeMemory(buffer);
}


NTSTATUS pLsaAddAccountRights(LSA_HANDLE lsa_h,
	PSID psid,
	PLSA_UNICODE_STRING rights,
	ULONG num_rights)
{
	HMODULE hm;
	typedef NTSTATUS(*LsaAddAccountRightsType)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
	static LsaAddAccountRightsType s_pLsaAddAccountRights = NULL;

	if (!s_pLsaAddAccountRights) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
			return STATUS_ASSERTION_FAILURE;

		if ((s_pLsaAddAccountRights = (LsaAddAccountRightsType)get_proc_address(hm, "LsaAddAccountRights")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}
	
	return s_pLsaAddAccountRights(lsa_h, psid, rights, num_rights);
}

ULONG pRtlNtStatusToDosError(NTSTATUS status)
{
	HMODULE hm;
	typedef ULONG(*RtlNtStatusToDosErrorType)(NTSTATUS);
	static RtlNtStatusToDosErrorType s_pRtlNtStatusToDosError = NULL;

	if (!s_pRtlNtStatusToDosError) {
		if ((hm = load_ntdll()) == NULL)
			return STATUS_ASSERTION_FAILURE;

		if ((s_pRtlNtStatusToDosError = (RtlNtStatusToDosErrorType)get_proc_address(hm, "RtlNtStatusToDosError")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}

	return pRtlNtStatusToDosError(status);
}

NTSTATUS pLsaClose(LSA_HANDLE lsa_h)
{
	HMODULE hm;
	typedef NTSTATUS(*LsaCloseType)(LSA_HANDLE);
	static LsaCloseType s_pLsaClose = NULL;

	if (!s_pLsaClose) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
			return STATUS_ASSERTION_FAILURE;

		if ((s_pLsaClose = (LsaCloseType)get_proc_address(hm, "LsaClose")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}

	return s_pLsaClose(lsa_h);
}