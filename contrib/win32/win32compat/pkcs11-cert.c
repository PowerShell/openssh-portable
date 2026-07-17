/*
 * Copyright (c) 2026 Sebastian Ott.  All rights reserved.
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

#include "authfd.h"
#include "digest.h"
#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"
#include "xmalloc.h"

#include "pkcs11-cert.h"

char *
pkcs11_identity_name(const struct sshkey *key, const u_char *blob,
    size_t blob_len)
{
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	char *name;
	size_t i, digest_len;

	if (!sshkey_is_cert(key))
		return sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT);
	digest_len = ssh_digest_bytes(SSH_DIGEST_SHA256);
	if (ssh_digest_memory(SSH_DIGEST_SHA256, blob, blob_len, digest,
	    sizeof(digest)) != 0)
		return NULL;
	name = xmalloc(5 + digest_len * 2 + 1);
	memcpy(name, "cert-", 5);
	for (i = 0; i < digest_len; i++)
		snprintf(name + 5 + i * 2, 3, "%02x", digest[i]);
	return name;
}

const char *
pkcs11_identity_comment(const char *provider, const char *label)
{
	return label == NULL || *label == '\0' ? provider : label;
}

void
free_pkcs11_certs(struct sshkey **certs, size_t ncerts)
{
	size_t i;

	for (i = 0; i < ncerts; i++)
		sshkey_free(certs[i]);
	free(certs);
}

int
parse_pkcs11_add_constraints(struct sshbuf *m, int *cert_onlyp,
    struct sshkey ***certsp, size_t *ncertsp)
{
	struct sshbuf *b = NULL;
	struct sshkey *key = NULL;
	char *ext_name = NULL;
	u_char ctype, value;
	u_int seconds;
	int r, seen = 0, seen_lifetime = 0, seen_confirm = 0;
	int seen_destinations = 0;

	if (m == NULL || cert_onlyp == NULL || certsp == NULL ||
	    ncertsp == NULL || *certsp != NULL || *ncertsp != 0)
		return SSH_ERR_INVALID_ARGUMENT;
	*cert_onlyp = 0;

	while (sshbuf_len(m) != 0) {
		if ((r = sshbuf_get_u8(m, &ctype)) != 0)
			goto out;
		if (ctype == SSH_AGENT_CONSTRAIN_LIFETIME) {
			if (seen_lifetime ||
			    (r = sshbuf_get_u32(m, &seconds)) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			seen_lifetime = 1;
			continue;
		}
		if (ctype == SSH_AGENT_CONSTRAIN_CONFIRM) {
			if (seen_confirm) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			seen_confirm = 1;
			continue;
		}
		if (ctype != SSH_AGENT_CONSTRAIN_EXTENSION) {
			error_f("unsupported smartcard constraint %u", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			goto out;
		}
		if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0)
			goto out;
		if (strcmp(ext_name,
		    "restrict-destination-v00@openssh.com") == 0) {
			if (seen_destinations || sshbuf_skip_string(m) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			seen_destinations = 1;
			free(ext_name);
			ext_name = NULL;
			continue;
		}
		if (strcmp(ext_name,
		    "associated-certs-v00@openssh.com") != 0) {
			error_f("unsupported smartcard constraint \"%s\"",
			    ext_name);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			goto out;
		}
		if (seen) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		seen = 1;
		if ((r = sshbuf_get_u8(m, &value)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0)
			goto out;
		*cert_onlyp = value != 0;
		while (sshbuf_len(b) != 0) {
			if (*ncertsp >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			if ((r = sshkey_froms(b, &key)) != 0)
				goto out;
			*certsp = xrecallocarray(*certsp, *ncertsp,
			    *ncertsp + 1, sizeof(**certsp));
			(*certsp)[(*ncertsp)++] = key;
			key = NULL;
		}
		sshbuf_free(b);
		b = NULL;
		free(ext_name);
		ext_name = NULL;
	}
	r = 0;
 out:
	sshkey_free(key);
	sshbuf_free(b);
	free(ext_name);
	return r;
}
