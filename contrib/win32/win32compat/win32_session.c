/*
 * Author: Mitch Gaffigan <mitch.gaffigan@comcast.net>
 *
 * Support for running a session inside the user's existing physical console
 * session (WTS session) instead of the service session.
 *
 * Copyright (c) 2026 Mitch Gaffigan
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <Windows.h>

#include "w32api_proxies.h"
#include "misc_internal.h"
#include "Debug.h"

/* set from sshd_config's AttachToConsoleSession, armed only for the post-auth spawn */
int attach_to_console_session = 0;

/* union so the SID stays suitably aligned */
typedef union {
	SID sid;
	BYTE buf[SECURITY_MAX_SID_SIZE];
} sid_buf;

/* returns 1 on success, 0 on failure */
static int
copy_token_user_sid(HANDLE token, sid_buf *out)
{
	/* union so the sid that follows the TOKEN_USER stays aligned */
	union {
		TOKEN_USER token_user;
		BYTE buf[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
	} u;
	DWORD len = 0;

	if (GetTokenInformation(token, TokenUser, &u, sizeof(u), &len) == FALSE) {
		error_f("GetTokenInformation(TokenUser) failed with error:%d", GetLastError());
		return 0;
	}

	if (CopySid(sizeof(out->buf), &out->sid, u.token_user.User.Sid) == FALSE) {
		error_f("CopySid failed with error:%d", GetLastError());
		return 0;
	}

	return 1;
}

static BOOL
tokens_same_user(HANDLE a, HANDLE b)
{
	sid_buf a_sid, b_sid;

	if (!copy_token_user_sid(a, &a_sid) || !copy_token_user_sid(b, &b_sid))
		return FALSE;

	return EqualSid(&a_sid.sid, &b_sid.sid);
}

/* needs no privilege, so use it to avoid WTSQueryUserToken at the logon screen */
static int
console_session_is_active(DWORD session_id)
{
	WTS_CONNECTSTATE_CLASS *state = NULL;
	DWORD len = 0;
	int ret = 0;

	if (pWTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id,
	    WTSConnectState, (LPWSTR *)&state, &len) == FALSE) {
		debug3_f("WTSQuerySessionInformationW failed for session:%u error:%d",
		    session_id, GetLastError());
		return 0;
	}

	if (state == NULL || len < sizeof(*state)) {
		debug3_f("unexpected WTSConnectState result for session:%u", session_id);
		goto done;
	}

	if (*state != WTSActive) {
		debug_f("nobody is logged on to console session:%u", session_id);
		goto done;
	}

	ret = 1;
done:
	if (state)
		pWTSFreeMemory(state);

	return ret;
}

/*
 * WTSQueryUserToken returns the filtered token for an administrator on a UAC
 * enabled system.  sshd sessions are elevated today, so follow the linked token
 * to keep that behavior.  Returns the token to use, closing the original if it
 * was replaced.
 */
static HANDLE
elevate_token(HANDLE token)
{
	TOKEN_ELEVATION_TYPE elevation_type;
	TOKEN_LINKED_TOKEN linked;
	HANDLE primary = NULL;
	DWORD len = 0;

	if (GetTokenInformation(token, TokenElevationType, &elevation_type,
	    sizeof(elevation_type), &len) == FALSE) {
		debug3_f("GetTokenInformation(TokenElevationType) failed with error:%d",
		    GetLastError());
		return token;
	}

	/* standard users and UAC disabled systems have no linked token */
	if (elevation_type != TokenElevationTypeLimited)
		return token;

	if (GetTokenInformation(token, TokenLinkedToken, &linked, sizeof(linked), &len) == FALSE) {
		debug_f("GetTokenInformation(TokenLinkedToken) failed with error:%d, "
		    "continuing with the filtered token", GetLastError());
		return token;
	}

	/* the linked token is an impersonation token, we need a primary one */
	if (DuplicateTokenEx(linked.LinkedToken, TOKEN_ALL_ACCESS, NULL,
	    SecurityImpersonation, TokenPrimary, &primary) == FALSE) {
		debug_f("DuplicateTokenEx failed with error:%d, "
		    "continuing with the filtered token", GetLastError());
		CloseHandle(linked.LinkedToken);
		return token;
	}

	debug3_f("using the linked elevated token");
	CloseHandle(linked.LinkedToken);
	CloseHandle(token);

	return primary;
}

/*
 * Returns a primary token for the physical console session, or NULL when there
 * is no such session or it belongs to a user other than authenticated_token.
 * The caller owns the returned handle.
 */
HANDLE
get_console_session_token(HANDLE authenticated_token)
{
	HANDLE token = NULL;
	DWORD console_session_id;

	console_session_id = WTSGetActiveConsoleSessionId();
	if (console_session_id == 0xFFFFFFFF || console_session_id == 0) {
		debug_f("no physical console session is attached");
		return NULL;
	}

	if (!console_session_is_active(console_session_id))
		return NULL;

	if (pWTSQueryUserToken(console_session_id, &token) == FALSE) {
		DWORD err = GetLastError();

		if (err == ERROR_PRIVILEGE_NOT_HELD)
			error_f("WTSQueryUserToken needs SeTcbPrivilege, ensure the sshd "
			    "service has TCB privileges");
		else
			debug_f("WTSQueryUserToken failed for session:%u error:%d",
			    console_session_id, err);

		return NULL;
	}

	if (!tokens_same_user(token, authenticated_token)) {
		debug_f("console session:%u belongs to a different user, not attaching",
		    console_session_id);
		CloseHandle(token);
		return NULL;
	}

	token = elevate_token(token);

	verbose("attaching session to console session %u", console_session_id);

	return token;
}
