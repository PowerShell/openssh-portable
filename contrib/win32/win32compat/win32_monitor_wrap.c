

#include "includes.h"

#include <sys/types.h>
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


void* mm_auth_pubkey(const char* user_name, const struct sshkey *key, 
    const u_char *sig, size_t slen, struct sshbuf* b) 
{
	/* Pass key challenge material to ssh-agent to retrieve token upon successful authentication */
	struct sshbuf *msg = NULL;
	u_char *blob = NULL;
	size_t blen = 0;
	DWORD token = 0;
	extern int auth_sock;
	int r = 0;
	int ssh_request_reply(int, struct sshbuf *, struct sshbuf *);

	while (1) {
		msg = sshbuf_new();
		if (!msg)
			fatal("%s: out of memory", __func__);
		if ((r = sshbuf_put_u8(msg, 0)) != 0 ||
			(r = sshbuf_put_cstring(msg, "pubkeyauth")) != 0 ||
			(r = sshkey_to_blob(key, &blob, &blen)) != 0 ||
			(r = sshbuf_put_string(msg, blob, blen)) != 0 ||
			(r = sshbuf_put_cstring(msg, user_name)) != 0 ||
			(r = sshbuf_put_string(msg, sig, slen)) != 0 ||
			(r = sshbuf_put_string(msg, sshbuf_ptr(b), sshbuf_len(b))) != 0 ||
			(r = ssh_request_reply(auth_sock, msg, msg)) != 0 ||
			(r = sshbuf_get_u32(msg, &token)) != 0) {
			debug("auth agent did not authorize client %s", user_name);
			break;
		}

		debug3("auth agent authenticated %s", user_name);
		break;

	}
	if (blob)
		free(blob);
	if (msg)
		sshbuf_free(msg);

	return NULL;
}