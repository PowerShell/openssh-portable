#include <Windows.h>
#include "misc_internal.h"
#include "signal_internal.h"
#include "inc\unistd.h"
#include "debug.h"

int posix_spawn_internal(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], HANDLE user_token, BOOLEAN prepend_module_path);

int
__posix_spawn_asuser(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], char* user)
{
	extern HANDLE password_auth_token;
	extern HANDLE sspi_auth_user;

	int r = -1;
	/* use token generated from password auth if already present */
	HANDLE user_token = NULL;
	HANDLE profile = NULL;
	HANDLE profile_token = NULL;
	pid_t pid = 0;
	BOOLEAN token_from_sspi = FALSE;
	BOOLEAN token_from_password_auth = FALSE;

	if (password_auth_token) {
		user_token = password_auth_token;
		token_from_password_auth = TRUE;
	}
	else if (sspi_auth_user) {
		user_token = sspi_auth_user;
		token_from_sspi = TRUE;
	}

	if (!user_token) {
		if ((user_token = get_user_token(user, 1)) == NULL) {
			error("unable to get security token for user %s", user);
			errno = EOTHER;
			return -1;
		}
	}
	if (strcmp(user, "sshd")) {
		profile = load_user_profile(user_token, user);
		if (profile != NULL) {
			/* least-privilege token copy kept for unload at child exit */
			if (!DuplicateHandle(GetCurrentProcess(), user_token, GetCurrentProcess(),
			    &profile_token, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, FALSE, 0)) {
				debug3("%s: DuplicateHandle() failed with error %d.", __FUNCTION__, GetLastError());
				profile_token = NULL;
			}
		}
	}

	r = posix_spawn_internal(&pid, path, file_actions, attrp, argv, envp, user_token, TRUE);

	if (pidp && r == 0)
		*pidp = pid;

	if (profile != NULL) {
		BOOLEAN child_has_profile = FALSE;
		if (r == 0 && profile_token != NULL)
			child_has_profile = (register_child_profile(pid, profile, profile_token) == 0);

		if (!child_has_profile) {
			unload_user_profile(profile_token ? profile_token : user_token, profile);
			if (profile_token)
				CloseHandle(profile_token);
		}
	}

	/* token ownership: SSPI token is freed by the GSS credential, not here */
	if (!token_from_sspi) {
		CloseHandle(user_token);
		if (token_from_password_auth)
			password_auth_token = NULL;
	}
	return r;
}
