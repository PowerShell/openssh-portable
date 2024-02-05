/* $OpenBSD: ssh-sk-client.c,v 1.12 2022/01/14 03:34:00 djm Exp $ */
/*
 * Copyright (c) 2019 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "msg.h"
#include "digest.h"
#include "pathnames.h"
#include "ssh-sk.h"
#include "misc.h"

/* #define DEBUG_SK 1 */

#ifdef WINDOWS
extern HANDLE sshagent_client_primary_token = NULL;
extern char *sshagent_con_username = NULL;
static char module_path[PATH_MAX + 1];

static char *
find_helper_in_module_path(void)
{
	wchar_t path[PATH_MAX + 1];
	DWORD n;
	char *ep;

	memset(module_path, 0, sizeof(module_path));
	memset(path, 0, sizeof(path));
	if ((n = GetModuleFileNameW(NULL, path, PATH_MAX)) == 0 ||
	    n >= PATH_MAX) {
		error_f("GetModuleFileNameW failed");
		return NULL;
	}
	if (wcstombs_s(NULL, module_path, sizeof(module_path), path,
	    sizeof(module_path) - 1) != 0) {
		error_f("wcstombs_s failed");
		return NULL;
	}
	if ((ep = strrchr(module_path, '\\')) == NULL) {
		error_f("couldn't locate trailing \\");
		return NULL;
	}
	*(++ep) = '\0'; /* trim */
	strlcat(module_path, "ssh-sk-helper.exe", sizeof(module_path) - 1);

	return module_path;
}

static char *
find_helper(void)
{
	char *helper = NULL;
	char module_path[PATH_MAX + 1];
	char *ep;
	DWORD n;
	size_t len = 0;

	_dupenv_s(&helper, &len, "SSH_SK_HELPER");
	if (helper == NULL || len == 0) {
		if ((helper = find_helper_in_module_path()) == NULL)
			helper = _PATH_SSH_SK_HELPER;
	}

	if (!path_absolute(helper)) {
		error_f("helper \"%s\" unusable: path not absolute", helper);
		return NULL;
	}
	debug_f("using \"%s\" as helper", helper);

	return helper;
}
#endif /* WINDOWS */

static int
start_helper(int *fdp, pid_t *pidp, void (**osigchldp)(int))
{
	void (*osigchld)(int);
	int oerrno, pair[2];
	pid_t pid;
	char *helper, *verbosity = NULL;
#ifdef WINDOWS
	int r, actions_inited = 0;
	char *av[3];
	posix_spawn_file_actions_t actions;
#endif

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;
#ifdef WINDOWS
	r = SSH_ERR_SYSTEM_ERROR;
	pair[0] = pair[1] = -1;
#endif

#ifdef WINDOWS
	if ((helper = find_helper()) == NULL)
		goto out;
#else
	helper = getenv("SSH_SK_HELPER");
	if (helper == NULL || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
	if (access(helper, X_OK) != 0) {
		oerrno = errno;
		error_f("helper \"%s\" unusable: %s", helper, strerror(errno));
		errno = oerrno;
		return SSH_ERR_SYSTEM_ERROR;
	}
#endif

#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Start helper */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
#ifdef WINDOWS
		goto out;
#else
		return SSH_ERR_SYSTEM_ERROR;
#endif
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

#ifdef WINDOWS
	if (posix_spawn_file_actions_init(&actions) != 0) {
		error_f("posix_spawn_file_actions_init failed");
		goto out;
	}
	actions_inited = 1;
	if (posix_spawn_file_actions_adddup2(&actions, pair[1],
	    STDIN_FILENO) != 0 ||
	    posix_spawn_file_actions_adddup2(&actions, pair[1],
	    STDOUT_FILENO) != 0) {
		error_f("posix_spawn_file_actions_adddup2 failed");
		goto out;
	}
#endif

#ifdef WINDOWS
	av[0] = helper;
	av[1] = verbosity;
	av[2] = NULL;

	if (sshagent_con_username) {
		debug_f("sshagent_con_username:%s", sshagent_con_username);
		if (!sshagent_client_primary_token) {
			error_f("sshagent_client_primary_token is NULL for user:%s", sshagent_con_username);
			goto out;
		}

		if (posix_spawnp_as_user((pid_t*)&pid, av[0], &actions, NULL, av, NULL, sshagent_client_primary_token) != 0) {
			error_f("failed to spwan process %s", av[0]);
			goto out;
		}
	} else {
		if (posix_spawnp((pid_t *)&pid, av[0], &actions, NULL, av, NULL) != 0) {
			error_f("posix_spawnp failed");
			goto out;
		}
	}
	r = 0;
#else
	if ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		return SSH_ERR_SYSTEM_ERROR;
	}
	if (pid == 0) {
		if ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			error_f("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == NULL ? "" : verbosity);
		execlp(helper, helper, verbosity, (char *)NULL);
		error_f("execlp: %s", strerror(errno));
		_exit(1);
	}
	close(pair[1]);
#endif
	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
#ifdef WINDOWS
	pair[0] = -1;
out:
	if (pair[0] != -1)
		close(pair[0]);
	if (pair[1] != -1)
		close(pair[1]);
	if (actions_inited)
		posix_spawn_file_actions_destroy(&actions);

	return r;
#else
	return 0;
#endif
}

static int
reap_helper(pid_t pid)
{
	int status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	while (waitpid(pid, &status, 0) == -1) {
		if (errno == EINTR) {
			errno = 0;
			continue;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		return SSH_ERR_SYSTEM_ERROR;
	}
	if (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		return SSH_ERR_AGENT_FAILURE;
	} else if (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		return SSH_ERR_AGENT_FAILURE;
	}
	return 0;
}

static int
client_converse(struct sshbuf *msg, struct sshbuf **respp, u_int type)
{
	int oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	void (*osigchld)(int);
	struct sshbuf *req = NULL, *resp = NULL;
	*respp = NULL;

	if ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		return r;

	if ((req = sshbuf_new()) == NULL || (resp = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	if ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, msg)) != 0) {
		error_fr(r, "compose");
		goto out;
	}
	if ((r = ssh_msg_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		goto out;
	}
	if ((r = ssh_msg_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		goto out;
	}
	if ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		goto out;
	}
	if (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		goto out;
	}
	if (rtype == SSH_SK_HELPER_ERROR) {
		if ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		if (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		else
			r = -(int)rerr;
		goto out;
	} else if (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	if ((r2 = reap_helper(pid)) != 0) {
		if (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	if (r == 0) {
		*respp = resp;
		resp = NULL;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	return r;

}

int
sshsk_sign(const char *provider, struct sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const char *pin)
{
	int oerrno, r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *kbuf = NULL, *req = NULL, *resp = NULL;

	*sigp = NULL;
	*lenp = 0;

#ifndef ENABLE_SK
	return SSH_ERR_KEY_TYPE_UNKNOWN;
#endif

	if ((kbuf = sshbuf_new()) == NULL ||
	    (req = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshkey_private_serialize(key, kbuf)) != 0) {
		error_fr(r, "encode key");
		goto out;
	}
	if ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, NULL)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		goto out;
	}

	if ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		goto out;

	if ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	if (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = NULL;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	return r;
}

int
sshsk_enroll(int type, const char *provider_path, const char *device,
    const char *application, const char *userid, uint8_t flags,
    const char *pin, struct sshbuf *challenge_buf,
    struct sshkey **keyp, struct sshbuf *attest)
{
	int oerrno, r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *kbuf = NULL, *abuf = NULL, *req = NULL, *resp = NULL;
	struct sshkey *key = NULL;

	*keyp = NULL;
	if (attest != NULL)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	return SSH_ERR_KEY_TYPE_UNKNOWN;
#endif

	if (type < 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((abuf = sshbuf_new()) == NULL ||
	    (kbuf = sshbuf_new()) == NULL ||
	    (req = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		goto out;
	}

	if ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		goto out;

	if ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((r = sshkey_private_deserialize(kbuf, &key)) != 0) {
		error_fr(r, "encode");
		goto out;
	}
	if (attest != NULL && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		goto out;
	}

	/* success */
	r = 0;
	*keyp = key;
	key = NULL;
 out:
	oerrno = errno;
	sshkey_free(key);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	return r;
}

static void
sshsk_free_resident_key(struct sshsk_resident_key *srk)
{
	if (srk == NULL)
		return;
	sshkey_free(srk->key);
	freezero(srk->user_id, srk->user_id_len);
	free(srk);
}


void
sshsk_free_resident_keys(struct sshsk_resident_key **srks, size_t nsrks)
{
	size_t i;

	if (srks == NULL || nsrks == 0)
		return;

	for (i = 0; i < nsrks; i++)
		sshsk_free_resident_key(srks[i]);
	free(srks);
}

int
sshsk_load_resident(const char *provider_path, const char *device,
    const char *pin, u_int flags, struct sshsk_resident_key ***srksp,
    size_t *nsrksp)
{
	int oerrno, r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *kbuf = NULL, *req = NULL, *resp = NULL;
	struct sshkey *key = NULL;
	struct sshsk_resident_key *srk = NULL, **srks = NULL, **tmp;
	u_char *userid = NULL;
	size_t userid_len = 0, nsrks = 0;

	*srksp = NULL;
	*nsrksp = 0;

	if ((kbuf = sshbuf_new()) == NULL ||
	    (req = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		goto out;
	}

	if ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		goto out;

	while (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		if ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, NULL, NULL)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((r = sshkey_private_deserialize(kbuf, &key)) != 0) {
			error_fr(r, "decode key");
			goto out;
		}
		if ((srk = calloc(1, sizeof(*srk))) == NULL) {
			error_f("calloc failed");
			goto out;
		}
		srk->key = key;
		key = NULL;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = NULL;
		userid_len = 0;
		if ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    sizeof(*srks))) == NULL) {
			error_f("recallocarray keys failed");
			goto out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->key), srk->key->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = NULL;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = NULL;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_key(srk);
	sshsk_free_resident_keys(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(key);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	return r;
}
