

#include "includes.h"

#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#endif

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "ssh.h"
#ifdef WITH_OPENSSL
#include "dh.h"
#endif
#include "buffer.h"
#include "key.h"
#include "cipher.h"
#include "kex.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#include "packet.h"
#include "mac.h"
#include "log.h"
#include "auth-pam.h"
#include "monitor_wrap.h"
#include "atomicio.h"
#include "monitor_fdpass.h"
#include "misc.h"
#include "uuencode.h"

#include "channels.h"
#include "session.h"
#include "servconf.h"

#include "ssherr.h"
#include "priv-agent.h"

int priv_agent_sock = -1;
int ssh_request_reply(int, struct sshbuf *, struct sshbuf *);

int get_priv_agent_sock() 
{
	extern int auth_sock;
	char env_value[12]; /* enough to accomodate "ssh-agent"*/
	size_t tmp;

	if (priv_agent_sock != -1)
		return priv_agent_sock;

	/* check if auth_sock is populated and connected to "ssh-agent"*/
	if (auth_sock != -1 &&
	    getenv_s(&tmp, env_value, 12, SSH_AUTHSOCKET_ENV_NAME) == 0 &&
	    strncmp(env_value, "ssh-agent", 12) == 0 )
		priv_agent_sock = auth_sock;
	else {
		struct sockaddr_un sunaddr;
		int sock;

		memset(&sunaddr, 0, sizeof(sunaddr));
		sunaddr.sun_family = AF_UNIX;
		strlcpy(sunaddr.sun_path, "\\\\.\\pipe\\openssh-ssh-agent", sizeof(sunaddr.sun_path));

		if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			debug("%s: unable to create AF_UNIX socket, errno:%d", __func__, errno);
			return -1;
		}

		/* close on exec */
		if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
		    connect(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0) {
			close(sock);
			debug("%s: unable to connect to privileged agent, errno:%d", __func__, errno);
			return -1;
		}

		priv_agent_sock = sock;
	}

	return priv_agent_sock;
}


void* mm_auth_pubkey(const char* user_name, const struct sshkey *key, 
    const u_char *sig, size_t slen, struct sshbuf* b) 
{
	/* Pass key challenge material to privileged agent to retrieve token upon successful authentication */
	struct sshbuf *msg = NULL;
	u_char *blob = NULL;
	size_t blen = 0;
	DWORD token = 0;
	int agent_fd;

	while (1) {
		if ((agent_fd = get_priv_agent_sock()) == -1)
			break;

		msg = sshbuf_new();
		if (!msg)
			fatal("%s: out of memory", __func__);
		if (sshbuf_put_u8(msg, SSH_PRIV_AGENT_MSG_ID) != 0 ||
		    sshbuf_put_cstring(msg, PUBKEY_AUTH_REQUEST) != 0 ||
		    sshkey_to_blob(key, &blob, &blen) != 0 ||
		    sshbuf_put_string(msg, blob, blen) != 0 ||
		    sshbuf_put_cstring(msg, user_name) != 0 ||
		    sshbuf_put_string(msg, sig, slen) != 0 ||
		    sshbuf_put_string(msg, sshbuf_ptr(b), sshbuf_len(b)) != 0 ||
		    ssh_request_reply(agent_fd, msg, msg) != 0) {
			debug("unable to send pubkeyauth request");
			break;
		}

		if (sshbuf_get_u32(msg, &token) != 0) 
			break;

		debug3("%s authenticated via pubkey", user_name);
		break;

	}
	if (blob)
		free(blob);
	if (msg)
		sshbuf_free(msg);

	return (void*)token;
}

int mm_load_profile(const char* user_name, u_int token)
{
	struct sshbuf *msg = NULL;
	int agent_fd;
	u_char result = 0;

	while (1) {
		if ((agent_fd = get_priv_agent_sock()) == -1)
			break;

		msg = sshbuf_new();
		if (!msg)
			fatal("%s: out of memory", __func__);
		if (sshbuf_put_u8(msg, SSH_PRIV_AGENT_MSG_ID) != 0 ||
			sshbuf_put_cstring(msg, PUBKEY_AUTH_REQUEST) != 0 ||
			sshbuf_put_cstring(msg, user_name) != 0 ||
			sshbuf_put_u32(msg, token) != 0 ||
			ssh_request_reply(agent_fd, msg, msg) != 0) {
			debug("unable to send loadprofile request %s", user_name);
			break;
		}

		if (sshbuf_get_u8(msg, &result) != 0)
			break;

		debug3("%s authenticated via pubkey", user_name);
		break;

	}

	return result;
}