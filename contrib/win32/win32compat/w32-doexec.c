/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Support execution of commands on Win32 based operating systems.
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
#include "includes.h"

#include <unistd.h>
#include "xmalloc.h"
#include "packet.h"

#include "channels.h"
#include "hostfile.h"
#include "auth.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "pal_doexec.h"
#include "misc_internal.h"
#include "sshTelemetry.h"

#ifndef SUBSYSTEM_NONE
#define SUBSYSTEM_NONE				0
#endif
#ifndef SUBSYSTEM_EXT
#define SUBSYSTEM_EXT				1
#endif
#ifndef SUBSYSTEM_INT_SFTP
#define SUBSYSTEM_INT_SFTP			2
#endif
#ifndef SUBSYSTEM_INT_SFTP_ERROR
#define SUBSYSTEM_INT_SFTP_ERROR	3
#endif

/* import */
extern ServerOptions options;
extern struct sshauthopt *auth_opts;
int get_in_chroot();
char **
do_setup_env_proxy(struct ssh *, Session *, const char *);

/*
* do_exec* on Windows
* - Read and set user environment variables from registry
* - Build subsystem cmdline path
* - Interactive shell/commands are executed using ssh-shellhost.exe
* - ssh-shellhost.exe implements server-side PTY for Windows
*/
#define UTF8_TO_UTF16_WITH_CLEANUP(o, i) do {	\
	if (o != NULL) free(o);						\
	if ((o = utf8_to_utf16(i)) == NULL)			\
		goto cleanup;							\
} while (0)

#define GOTO_CLEANUP_ON_ERR(exp) do {	\
	if ((exp) != 0)						\
		goto cleanup;					\
} while(0)


static char*
get_registry_operation_error_message(const LONG error_code) 
{
	char* message = NULL;
	wchar_t* wmessage = NULL;
	DWORD length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, error_code, 0, (wchar_t*)&wmessage, 0, NULL);
	if (length == 0)
		return NULL;

	if (wmessage[length - 1] == L'\n')
		wmessage[length - 1] = L'\0';
	if (length > 1 && wmessage[length - 2] == L'\r')
		wmessage[length - 2] = L'\0';

	message = utf16_to_utf8(wmessage);
	LocalFree(wmessage);

	return message;
}

wchar_t*
get_registry_key_value(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD* required)
{
	wchar_t* data = NULL;
	LSTATUS ret = RegGetValueW(hKey, lpSubKey, lpValue, RRF_RT_REG_SZ, NULL, NULL, required); /* RRF_RT_REG_SZ: automatically converts REG_EXPAND_SZ to REG_SZ. */
	if (ret == ERROR_SUCCESS) {
		data = malloc(*required);
		if (data) {
			ret = RegGetValueW(hKey, lpSubKey, lpValue, RRF_RT_REG_SZ, NULL, (LPBYTE)data, required);
		}
	}
	if (ret != ERROR_SUCCESS) {
		char* error_message = get_registry_operation_error_message(ret);
		char* subkey = utf16_to_utf8(lpSubKey);
		char* value = utf16_to_utf8(lpValue);
		if (error_message && subkey && value) {
			error("Failed to get the value for registry key %s\\%s. %s", subkey, value, error_message);
		}
		else {
			error("Failed to get the registry key value.");
		}
		if (error_message)
			free(error_message);
		if (subkey)
			free(subkey);
		if (value)
			free(value);
		if (data) { /* Reset data on errors. */
			free(data);
			data = NULL;
		}
	}
	return data;
}

/* Build the user environment block. */
/* Set the HOMEPATH variable (and optionally HOMEDRIVE) using the specified pw_dir_w profile path if they are not assigned. */
/* Set the PATH environment variable with values from the registry. */
static void
setup_session_user_vars(wchar_t* pw_dir_w)
{
	/* HOMEDRIVE and HOMEPATH are set by shell32!RegenerateUserEnvironment
	   which is called on explorer.exe initialization in the user context. */
	if (getenv("HOMEPATH") == NULL) {
		if (pw_dir_w[0] && pw_dir_w[1] == L':') {
			SetEnvironmentVariableW(L"HOMEPATH", pw_dir_w + 2);
			wchar_t wc = pw_dir_w[2];
			pw_dir_w[2] = L'\0';
			SetEnvironmentVariableW(L"HOMEDRIVE", pw_dir_w);
			pw_dir_w[2] = wc;
		}
		else {
			SetEnvironmentVariableW(L"HOMEPATH", pw_dir_w);
		}
	}

	/* PATH is a special case. The System Path value is prepended to the User Path value */
	DWORD hklm_path_sz = 0;
	DWORD hkcu_path_sz = 0;
	wchar_t* user_path = NULL;
	wchar_t* hklm_path = get_registry_key_value(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"PATH", &hklm_path_sz);
	wchar_t* hkcu_path = get_registry_key_value(HKEY_CURRENT_USER, L"Environment", L"PATH", &hkcu_path_sz);
	DWORD user_path_sz = hklm_path_sz + hkcu_path_sz;
	if (hklm_path && hkcu_path) {
		user_path = malloc(user_path_sz);
		if (user_path) {
			memcpy_s(user_path, user_path_sz, hklm_path, hklm_path_sz);
			user_path[hklm_path_sz / sizeof(wchar_t) - 1] = L';'; /* Replace trailing null with ';'. */
			memcpy_s(user_path + hklm_path_sz / sizeof(wchar_t), user_path_sz - hklm_path_sz, hkcu_path, hkcu_path_sz);
			SetEnvironmentVariableW(L"PATH", user_path);
			free(user_path);
		}
	}
	else if (hklm_path || hkcu_path) {
		user_path = hklm_path ? hklm_path : hkcu_path;
		SetEnvironmentVariableW(L"PATH", user_path);
	}
	if (hklm_path)
		free(hklm_path);
	if (hkcu_path)
		free(hkcu_path);
}

static int
setup_session_env(struct ssh *ssh, Session* s)
{
	int i = 0, ret = -1;
	char *env_name = NULL, *env_value = NULL, *t = NULL, **env = NULL;
	char buf[1024] = { 0 };
	wchar_t *env_name_w = NULL, *env_value_w = NULL, *pw_dir_w = NULL, *tmp = NULL, wbuf[1024] = { 0, };

	if (!s->is_subsystem) {
		_snprintf(buf, ARRAYSIZE(buf), "%s@%s", s->pw->pw_name, getenv("COMPUTERNAME"));
		UTF8_TO_UTF16_WITH_CLEANUP(tmp, buf);
		/* escape $ characters as $$ to distinguish from special prompt characters */
		for (size_t i = 0, j = 0; i < wcslen(tmp) && j < ARRAYSIZE(wbuf) - 1; i++) {
			wbuf[j] = tmp[i];
			if (wbuf[j++] == L'$')
				wbuf[j++] = L'$';
		}
		wcscat_s(wbuf, ARRAYSIZE(wbuf), L" $P$G");
		SetEnvironmentVariableW(L"PROMPT", wbuf);
	}

	UTF8_TO_UTF16_WITH_CLEANUP(pw_dir_w, s->pw->pw_dir);
	setup_session_user_vars(pw_dir_w); /* setup user specific env variables */

	env = do_setup_env_proxy(ssh, s, s->pw->pw_shell);
	while (env_name = env[i]) {
		if (t = strstr(env[i++], "=")) {
			/* SKIP, if not applicable on WINDOWS
			PATH is already set.
			MAIL is not applicable.
			*/
			if ((0 == strncmp(env_name, "PATH=", strlen("PATH="))) ||
				(0 == strncmp(env_name, "MAIL=", strlen("MAIL=")))) {
				continue;
			}

			env_value = t + 1;
			*t = '\0';
			UTF8_TO_UTF16_WITH_CLEANUP(env_name_w, env_name);
			UTF8_TO_UTF16_WITH_CLEANUP(env_value_w, env_value);
			SetEnvironmentVariableW(env_name_w, env_value_w);
		}
	}
	ret = 0;

cleanup:
	if (pw_dir_w)
		free(pw_dir_w);
	if (tmp)
		free(tmp);
	if (env_name_w)
		free(env_name_w);
	if (env_value_w)
		free(env_value_w);
	if (env) {
		i = 0;
		while (t = env[i++])
			free(t);
		free(env);
	}
	return ret;
}

int do_exec_windows(struct ssh *ssh, Session *s, const char *command, int pty) {
	int pipein[2], pipeout[2], pipeerr[2], ret = -1;
	char *exec_command = NULL, *posix_cmd_input = NULL, *shell = NULL, *pty_cmd_cp = NULL;;
	HANDLE job = NULL, process_handle;
	extern char* shell_command_option;
	extern char* shell_arguments;
	extern BOOLEAN arg_escape;

	/* Create three pipes for stdin, stdout and stderr */
	if (pipe(pipein) == -1 || pipe(pipeout) == -1 || pipe(pipeerr) == -1)
		goto cleanup;

	set_nonblock(pipein[0]);
	set_nonblock(pipein[1]);
	set_nonblock(pipeout[0]);
	set_nonblock(pipeout[1]);
	set_nonblock(pipeerr[0]);
	set_nonblock(pipeerr[1]);

	fcntl(pipein[1], F_SETFD, FD_CLOEXEC);
	fcntl(pipeout[0], F_SETFD, FD_CLOEXEC);
	fcntl(pipeerr[0], F_SETFD, FD_CLOEXEC);

	/* setup Environment varibles */
	do {
		static int environment_set = 0;

		if (environment_set)
			break;

		if (setup_session_env(ssh, s) != 0)
			goto cleanup;

		environment_set = 1;
	} while (0);
	int in_chroot = get_in_chroot();
	if (!in_chroot)
		chdir(s->pw->pw_dir);

	if (s->is_subsystem >= SUBSYSTEM_INT_SFTP_ERROR) {
		command = "echo This service allows sftp connections only.";
		pty = 0;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;
	HANDLE job_dup;
	pid_t pid = -1;
	char* shell_command_option_local = NULL;
	size_t shell_len = 0;
	/*account for the quotes and null*/
	shell_len = strlen(s->pw->pw_shell) + 2 + 1;
	if ((shell = malloc(shell_len)) == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	sprintf_s(shell, shell_len, "\"%s\"", s->pw->pw_shell);
	debug3("shell: %s", shell);

	enum sh_type { SH_OTHER, SH_CMD, SH_PS, SH_BASH, SH_CYGWIN, SH_SHELLHOST } shell_type = SH_OTHER;
	/* get shell type */
	if (strstr(s->pw->pw_shell, "system32\\cmd"))
		shell_type = SH_CMD;
	else if (strstr(s->pw->pw_shell, "powershell"))
		shell_type = SH_PS;
	else if (strstr(s->pw->pw_shell, "ssh-shellhost"))
		shell_type = SH_SHELLHOST;
	else if (strstr(s->pw->pw_shell, "\\bash"))
		shell_type = SH_BASH;
	else if (strstr(s->pw->pw_shell, "cygwin"))
		shell_type = SH_CYGWIN;

	if (shell_command_option)
		shell_command_option_local = shell_command_option;
	else if (shell_type == SH_CMD)
		shell_command_option_local = "/c";
	else
		shell_command_option_local = "-c";
	debug3("shell_option: %s", shell_command_option_local);
	send_shell_telemetry(pty, shell_type);

	if (pty) {
		fcntl(s->ptyfd, F_SETFD, FD_CLOEXEC);
		char *pty_cmd = NULL;
		if (command) {
			size_t len = strlen(shell) + 1 + strlen(shell_command_option_local) + 1 + strlen(command) + 1;
			pty_cmd_cp = pty_cmd = calloc(1, len);
			if (pty_cmd != NULL)
			{
				strcpy_s(pty_cmd, len, shell);
				strcat_s(pty_cmd, len, " ");
				strcat_s(pty_cmd, len, shell_command_option_local);
				strcat_s(pty_cmd, len, " ");
				strcat_s(pty_cmd, len, command);
			}
		} else {
			if (shell_arguments) {
				size_t len = strlen(shell) + 1 + strlen(shell_arguments) + 1;
				pty_cmd = calloc(1, len);

				if (pty_cmd != NULL)
				{
					strcpy_s(pty_cmd, len, shell);
					strcat_s(pty_cmd, len, " ");
					strcat_s(pty_cmd, len, shell_arguments);
				}
			}
			else
				pty_cmd = shell;
		}

		if (exec_command_with_pty(&pid, pty_cmd, pipein[0], pipeout[1], pipeerr[1], s->col, s->row, s->ttyfd) == -1)
			goto cleanup;
		close(s->ttyfd);
		s->ttyfd = -1;
	}
	else {
		posix_spawn_file_actions_t actions;
		char *spawn_argv[4] = { NULL, };
		exec_command = build_exec_command(command);
		debug3("exec_command: %s", exec_command);

		if (shell_type == SH_PS || shell_type == SH_BASH ||
			shell_type == SH_CYGWIN || (shell_type == SH_OTHER) && arg_escape) {
			spawn_argv[0] = shell;

			if (exec_command) {
				spawn_argv[1] = shell_command_option_local;
				spawn_argv[2] = exec_command;
			}
		}
		else {
			/*
			 * no escaping needed for cmd and ssh-shellhost, or escaping is disabled
			 * in registry; pass shell, shell option, and quoted command as cmd path
			 * of posix_spawn to avoid escaping
			 */
			size_t posix_cmd_input_len = strlen(shell) + 1;

			/* account for " around and null */
			if (exec_command) {
				posix_cmd_input_len += strlen(shell_command_option_local) + 1;
				posix_cmd_input_len += strlen(exec_command) + 2 + 1;
			}

			if ((posix_cmd_input = malloc(posix_cmd_input_len)) == NULL) {
				errno = ENOMEM;
				goto cleanup;
			}

			if (exec_command) {
				sprintf_s(posix_cmd_input, posix_cmd_input_len, "%s %s \"%s\"",
					shell, shell_command_option_local, exec_command);
			} else {
				sprintf_s(posix_cmd_input, posix_cmd_input_len, "%s",
					shell); 
			}

			spawn_argv[0] = posix_cmd_input;
		}
		debug3("arg escape option: %s", arg_escape ? "TRUE":"FALSE");
		debug3("spawn_argv[0]: %s", spawn_argv[0]);

		if (posix_spawn_file_actions_init(&actions) != 0 ||
			posix_spawn_file_actions_adddup2(&actions, pipein[0], STDIN_FILENO) != 0 ||
			posix_spawn_file_actions_adddup2(&actions, pipeout[1], STDOUT_FILENO) != 0 ||
			posix_spawn_file_actions_adddup2(&actions, pipeerr[1], STDERR_FILENO) != 0) {
			errno = EOTHER;
			error("posix_spawn initialization failed");
			goto cleanup;
		}
		
		//Passing the PRIVSEP_LOG_FD (STDERR_FILENO + 2) to sftp-server for logging
		if (exec_command) {
			if (strstr(exec_command, "sftp-server.exe")) {
				if (posix_spawn_file_actions_adddup2(&actions, STDERR_FILENO + 2, SFTP_SERVER_LOG_FD) != 0) {
					errno = EOTHER;
					error("posix_spawn initialization failed");
					goto cleanup;
				}
			}
		}

		if (posix_spawn(&pid, spawn_argv[0], &actions, NULL, spawn_argv, NULL) != 0) {
			errno = EOTHER;
			error("posix_spawn: %s", strerror(errno));
			goto cleanup;
		}
		posix_spawn_file_actions_destroy(&actions);
	}

	memset(&job_info, 0, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
	job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;

	if ((process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL) {
		errno = EOTHER;
		error("cannot get process handle: %d", GetLastError());
		goto cleanup;
	}

	/*
	* assign job object to control processes spawned
	* 1. create job object
	* 2. assign child to job object
	* 3. duplicate job handle into child so it would be the last to close it
	*/
	if ((job = CreateJobObjectW(NULL, NULL)) == NULL ||
		!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info)) ||
		!AssignProcessToJobObject(job, process_handle) ||
		!DuplicateHandle(GetCurrentProcess(), job, process_handle, &job_dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		errno = EOTHER;
		error("cannot associate job object: %d", GetLastError());
		TerminateProcess(process_handle, 255);
		CloseHandle(process_handle);
		goto cleanup;
	}
	s->pid = pid;

	/* Close the child sides of the socket pairs. */
	close(pipein[0]);
	close(pipeout[1]);
	close(pipeerr[1]);

	/*
	* Enter the interactive session.  Note: server_loop must be able to
	* handle the case that fdin and fdout are the same.
	*/
	if (pty) {
		/* Set interactive/non-interactive mode */
		ssh_packet_set_interactive(ssh, 1, options.ip_qos_interactive,
			options.ip_qos_bulk);
		session_set_fds(ssh, s, pipein[1], pipeout[0], -1, 1, 1);
	}
	else {
		/* Set interactive/non-interactive mode */
		ssh_packet_set_interactive(ssh, s->display != NULL, options.ip_qos_interactive,
			options.ip_qos_bulk);
		session_set_fds(ssh, s, pipein[1], pipeout[0], pipeerr[0], s->is_subsystem, 0);
	}

	ret = 0;

cleanup:
	if (exec_command)
		free(exec_command);
	if (posix_cmd_input)
		free(posix_cmd_input);
	if (shell)
		free(shell);
	if (job)
		CloseHandle(job);
	if (pty_cmd_cp)
		free(pty_cmd_cp);

	return ret;
}

int
do_exec_no_pty(struct ssh *ssh, Session *s, const char *command) {
	return do_exec_windows(ssh, s, command, 0);
}

int
do_exec_pty(struct ssh *ssh, Session *s, const char *command) {
	return do_exec_windows(ssh, s, command, 1);
}