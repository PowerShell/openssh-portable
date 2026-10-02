/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 * ssh-agent implementation on Windows
 * 
 * Copyright (c) 2015 Microsoft Corp.
 * All rights reserved
 *
 * Microsoft openssh win32 port
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

#include "agent.h"
#include "agent-request.h"
#include "config.h"
#include <sddl.h>
#include "xmalloc.h"
#include "keyagent-registry.h"
#include "keyagent-pkcs11.h"
#include "pkcs11-cert.h"

#pragma warning(push, 3)

int
process_unsupported_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	int r = 0;
	debug("ssh protocol 1 is not supported");
	if (sshbuf_put_u8(response, SSH_AGENT_FAILURE) != 0)
		r = -1;
	return r;
}

static int
parse_key_constraint_extension(struct sshbuf *m)
{
	char *ext_name = NULL, *skprovider = NULL;
	int r;

	if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {
		error_fr(r, "parse constraint extension");
		goto out;
	}
	debug_f("constraint ext %s", ext_name);
	if (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		if ((r = sshbuf_get_cstring(m, &skprovider, NULL)) != 0) {
			error_fr(r, "parse %s", ext_name);
			goto out;
		}
		if (strcmp(skprovider, "internal") != 0) {
			error_f("unsupported sk-provider: %s", skprovider);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			goto out;
		}
	} else {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(ext_name);
	return r;
}

static int
parse_key_constraints(struct sshbuf *m)
{
	int r;
	u_char ctype;

	while (sshbuf_len(m)) {
		if ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error("get constraint type returned %d", r);
			return r;
		}
		switch (ctype) {
		case SSH_AGENT_CONSTRAIN_EXTENSION:
			if ((r = parse_key_constraint_extension(m)) != 0)
				return r;
			break;
		default:
			error("Unknown constraint %d", ctype);
			return SSH_ERR_FEATURE_UNSUPPORTED;
		}
	}

	return 0;
}

int
process_add_identity(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	struct sshkey* key = NULL;
	int r = 0, blob_len, eblob_len, request_invalid = 0, success = 0;
	size_t comment_len, pubkey_blob_len;
	u_char *pubkey_blob = NULL;
	char *thumbprint = NULL, *comment = NULL, *cert_name = NULL;
	const char *blob;
	char* eblob = NULL;
	HKEY reg = 0, sub = 0, user_root = 0, token = 0;
	SECURITY_ATTRIBUTES sa;
	LSTATUS status;
	const wchar_t *names[] = { NULL, L"pub", L"type", L"comment",
	    L"provider" };
	u_char *saved[5] = { NULL };
	DWORD saved_type[5] = { 0 }, saved_len[5] = { 0 };
	DWORD disposition = 0, children = 0;
	const BYTE *value;
	DWORD value_len;
	ULONG sd_len = 0;
	int present[5] = { 0 }, i, changed = 0;
	struct sshkey *stored_cert = NULL;
	char *association = NULL;

	/* parse input request */
	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	blob = sshbuf_ptr(request);
	if (sshkey_private_deserialize(request, &key) != 0 ||
	   (blob_len = (sshbuf_ptr(request) - blob) & 0xffffffff) == 0 ||
	    sshbuf_get_cstring(request, &comment, &comment_len) != 0) {
		debug("key add request is invalid");
		request_invalid = 1;
		goto done;
	}

	if ((r = parse_key_constraints(request)) != 0) {
		if (r != SSH_ERR_FEATURE_UNSUPPORTED)
			request_invalid = 1;
		goto done;
	}

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);
	if ((!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sd_len)) ||
	    sshkey_to_blob(key, &pubkey_blob, &pubkey_blob_len) != 0 ||
	    convert_blob(con, blob, blob_len, &eblob, &eblob_len, 1) != 0 ||
	    ((thumbprint = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL) ||
	    get_user_root(con, &user_root) != 0 ||
	    RegCreateKeyExW(user_root, SSH_KEYS_ROOT, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &reg, NULL) != 0) {
		error("failed to open key store");
		goto done;
	}
	if (sshkey_is_cert(key)) {
		if ((cert_name = pkcs11_identity_name(key, pubkey_blob,
		    pubkey_blob_len)) == NULL)
			goto done;
		status = RegOpenKeyExA(reg, cert_name, 0,
		    KEY_QUERY_VALUE | KEY_WOW64_64KEY, &token);
		if (status != ERROR_FILE_NOT_FOUND && (status != ERROR_SUCCESS ||
		    read_agent_identity(token, con, &stored_cert, &association) != 0 ||
		    association == NULL || !sshkey_equal(key, stored_cert) ||
		    RegQueryInfoKeyW(token, NULL, NULL, NULL, &children, NULL,
		    NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS ||
		    children != 0)) {
			error("invalid existing token certificate");
			goto done;
		}
	}
	if (RegCreateKeyExA(reg, thumbprint, 0, 0, 0,
	    KEY_WRITE | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sa, &sub,
	    &disposition) != ERROR_SUCCESS)
		goto done;
	if (disposition == REG_OPENED_EXISTING_KEY) {
		for (i = 0; i < 5; i++) {
			if (read_optional_reg_value(sub, names[i], &present[i],
			    &saved_type[i], &saved[i], &saved_len[i]) != 0)
				goto done;
		}
	}
	for (i = 0; i < 4; i++) {
		switch (i) {
		case 0: value = (BYTE *)eblob; value_len = eblob_len; break;
		case 1: value = pubkey_blob; value_len = (DWORD)pubkey_blob_len; break;
		case 2: value = (BYTE *)&key->type; value_len = sizeof(key->type); break;
		default: value = (BYTE *)comment; value_len = (DWORD)comment_len; break;
		}
		if (RegSetValueExW(sub, names[i], 0,
		    i == 2 ? REG_DWORD : REG_BINARY, value, value_len) != ERROR_SUCCESS) {
			error("failed to add key to store");
			goto done;
		}
		changed++;
	}
	/* A software key does not belong to a PKCS#11 provider. */
	status = RegDeleteValueW(sub, L"provider");
	if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
		goto done;
	changed = 5;
	/* Atomic deletion: a failing delete must leave the token entry intact. */
	if (token != NULL && RegDeleteKeyExA(reg, cert_name,
	    KEY_WOW64_64KEY, 0) != ERROR_SUCCESS) {
		error("failed to detach token certificate");
		goto done;
	}

	debug("added key to store");
	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;

	/* delete created reg key if not succeeded*/
	if (!success && sub != NULL) {
		if (disposition == REG_CREATED_NEW_KEY) {
			if (RegDeleteKeyExA(reg, thumbprint, KEY_WOW64_64KEY, 0) != ERROR_SUCCESS)
				error("failed to remove incomplete software identity");
		} else {
			for (i = 0; i < changed; i++) {
				if (restore_optional_reg_value(sub, names[i], present[i],
				    saved_type[i], saved[i], saved_len[i]) != 0)
					error("failed to restore software identity value %d", i);
			}
		}
	}

	if (eblob) {
		SecureZeroMemory(eblob, eblob_len);
		free(eblob);
	}
	for (i = 0; i < 5; i++) {
		if (saved[i] != NULL)
			SecureZeroMemory(saved[i], saved_len[i]);
		free(saved[i]);
	}
	free(comment);
	free(cert_name);
	free(association);
	sshkey_free(stored_cert);
	if (token != NULL)
		RegCloseKey(token);
	if (sa.lpSecurityDescriptor)
		LocalFree(sa.lpSecurityDescriptor);
	if (key)
		sshkey_free(key);
	if (thumbprint)
		free(thumbprint);
	if (user_root)
		RegCloseKey(user_root);
	if (reg)
		RegCloseKey(reg);
	if (sub)
		RegCloseKey(sub);
	if (pubkey_blob)
		free(pubkey_blob);
	return r;
}

static int sign_blob(const struct sshkey *pubkey, u_char ** sig, size_t *siglen,
	const u_char *blob, size_t blen, u_int flags, struct agent_connection* con) 
{
	HKEY reg = 0, sub = 0, user_root = 0;
	int r = 0, success = 0;
	struct sshkey* prikey = NULL;
	char *thumbprint = NULL, *regdata = NULL, *algo = NULL;
	DWORD regdatalen = 0, keyblob_len = 0;
	struct sshbuf* tmpbuf = NULL;
	char *keyblob = NULL;
	const char *sk_provider = NULL;
	int is_pkcs11_key = 0;

	*sig = NULL;
	*siglen = 0;

	if ((prikey = keyagent_pkcs11_lookup_key(pubkey)) == NULL) {
		if ((thumbprint = sshkey_fingerprint(pubkey, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL ||
			get_user_root(con, &user_root) != 0 ||
			RegOpenKeyExW(user_root, SSH_KEYS_ROOT,
				0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS, &reg) != 0 ||
			RegOpenKeyExA(reg, thumbprint, 0,
				STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &sub) != 0 ||
			RegQueryValueExW(sub, NULL, 0, NULL, NULL, &regdatalen) != ERROR_SUCCESS ||
			(regdata = malloc(regdatalen)) == NULL ||
			RegQueryValueExW(sub, NULL, 0, NULL, regdata, &regdatalen) != ERROR_SUCCESS ||
			convert_blob(con, regdata, regdatalen, &keyblob, &keyblob_len, FALSE) != 0 ||
			(tmpbuf = sshbuf_from(keyblob, keyblob_len)) == NULL ||
			sshkey_private_deserialize(tmpbuf, &prikey) != 0) {
				error("cannot retrieve and deserialize key from registry");
				goto done;
			}
	}
	else
		is_pkcs11_key = 1;
	if (flags & SSH_AGENT_RSA_SHA2_256)
		algo = "rsa-sha2-256";
	else if (flags & SSH_AGENT_RSA_SHA2_512)
		algo = "rsa-sha2-512";

	if (sshkey_is_sk(prikey))
		sk_provider = "internal";
	if (sshkey_sign(prikey, sig, siglen, blob, blen, algo, sk_provider, NULL, 0) != 0) {
		error("cannot sign using retrieved key");
		goto done;
	}

	success = 1;

done:
	if (keyblob)
		free(keyblob);
	if (regdata)
		free(regdata);
	if (tmpbuf)
		sshbuf_free(tmpbuf);
	if (!is_pkcs11_key)
		if (prikey)
			sshkey_free(prikey);
	if (thumbprint)
		free(thumbprint);
	if (user_root)
		RegCloseKey(user_root);
	if (reg)
		RegCloseKey(reg);
	if (sub)
		RegCloseKey(sub);

	return success ? 0 : -1;
}

int
process_sign_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	u_char *blob, *data, *signature = NULL;
	size_t blen, dlen, slen = 0;
	u_int flags = 0;
	int r, request_invalid = 0, success = 0;
	struct sshkey *key = NULL;

	if (keyagent_pkcs11_reload_providers(con) != 0)
		goto done;

	if (sshbuf_get_string_direct(request, &blob, &blen) != 0 ||
	    sshbuf_get_string_direct(request, &data, &dlen) != 0 ||
	    sshbuf_get_u32(request, &flags) != 0 ||
	    sshkey_from_blob(blob, blen, &key) != 0) {
		debug("sign request is invalid");
		request_invalid = 1;
		goto done;
	}

	if (sign_blob(key, &signature, &slen, data, dlen, flags, con) != 0)
		goto done;

	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else {
		if (success) {
			if (sshbuf_put_u8(response, SSH2_AGENT_SIGN_RESPONSE) != 0 ||
			    sshbuf_put_string(response, signature, slen) != 0) {
				r = -1;
			}
		} else if (sshbuf_put_u8(response, SSH_AGENT_FAILURE) != 0)
				r = -1;
	}

	if (key)
		sshkey_free(key);
	if (signature)
		free(signature);
	keyagent_pkcs11_release();
	return r;
}

int
process_remove_key(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	HKEY user_root = 0, root = 0;
	char *blob, *thumbprint = NULL;
	size_t blen;
	int r = 0, success = 0, request_invalid = 0;
	struct sshkey *key = NULL;
	LSTATUS status;

	if (sshbuf_get_string_direct(request, &blob, &blen) != 0 ||
	    sshkey_from_blob(blob, blen, &key) != 0) { 
		request_invalid = 1;
		goto done;
	}

	if ((thumbprint = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL ||
	    get_user_root(con, &user_root) != 0 ||
	    RegOpenKeyExW(user_root, SSH_KEYS_ROOT, 0,
	    DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE |
	    KEY_WOW64_64KEY, &root) != 0)
		goto done;
	status = delete_matching_identity(root, thumbprint,
	    (const u_char *)blob, blen);
	if (status == ERROR_FILE_NOT_FOUND && sshkey_is_cert(key))
		status = keyagent_pkcs11_delete_cert_identity(root, key,
		    (const u_char *)blob, blen);
	if (status != ERROR_SUCCESS)
		goto done;
	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;

	if (key)
		sshkey_free(key);
	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	if (thumbprint)
		free(thumbprint);
	return r;
}
int 
process_remove_all(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	HKEY user_root = 0, root = 0;
	int r = 0;

	if (get_user_root(con, &user_root) != 0 ||
	    RegOpenKeyExW(user_root, SSH_AGENT_ROOT, 0,
		   DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &root) != 0) {
		goto done;
	}

	RegDeleteTreeW(root, SSH_KEYS_KEY);
	RegDeleteTreeW(root, SSH_PKCS11_PROVIDERS_KEY);
done:
	r = 0;
	if (sshbuf_put_u8(response, SSH_AGENT_SUCCESS) != 0)
		r = -1;

	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	return r;
}

int
process_request_identities(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	int count = 0, index = 0, success = 0, r = 0;
	HKEY root = NULL, sub = NULL, user_root = 0;
	char* count_ptr = NULL;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len = MAX_KEY_LENGTH;
	char *pkblob = NULL, *comment = NULL;
	DWORD regdatalen = 0, commentlen = 0, key_count = 0;
	struct sshbuf* identities;

	if ((identities = sshbuf_new()) == NULL)
		goto done;

	if ( get_user_root(con, &user_root) != 0 ||
	    RegOpenKeyExW(user_root, SSH_KEYS_ROOT, 0, STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &root) != 0) {
		success = 1;
		goto done;
	}

	while (1) {
		sub_name_len = MAX_KEY_LENGTH;
		if (sub) {
			RegCloseKey(sub);
			sub = NULL;
		}
		if (RegEnumKeyExW(root, index++, sub_name, &sub_name_len, NULL, NULL, NULL, NULL) == 0) {
			if (RegOpenKeyExW(root, sub_name, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sub) == 0 &&
				RegQueryValueExW(sub, L"pub", 0, NULL, NULL, &regdatalen) == 0 &&
				RegQueryValueExW(sub, L"comment", 0, NULL, NULL, &commentlen) == 0) {
				if (pkblob)
					free(pkblob);
				if (comment)
					free(comment);
				pkblob = NULL;
				comment = NULL;

				if ((pkblob = malloc(regdatalen)) == NULL ||
					(comment = malloc(commentlen)) == NULL ||
					RegQueryValueExW(sub, L"pub", 0, NULL, pkblob, &regdatalen) != 0 ||
					RegQueryValueExW(sub, L"comment", 0, NULL, comment, &commentlen) != 0 ||
					sshbuf_put_string(identities, pkblob, regdatalen) != 0 ||
					sshbuf_put_string(identities, comment, commentlen) != 0)
					goto done;

				key_count++;
			}
		} else
			break;

	}

	success = 1;
done:
	r = 0;
	if (success) {
		if (sshbuf_put_u8(response, SSH2_AGENT_IDENTITIES_ANSWER) != 0 ||
			sshbuf_put_u32(response, key_count) != 0 ||
			sshbuf_putb(response, identities) != 0)
			goto done;
	} else
		r = -1;

	if (pkblob)
		free(pkblob);
	if (comment)
		free(comment);
	if (identities)
		sshbuf_free(identities);
	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	if (sub)
		RegCloseKey(sub);
	return r;
}

extern int timingsafe_bcmp(const void* b1, const void* b2, size_t n);

static int
buf_equal(const struct sshbuf *a, const struct sshbuf *b)
{
	if (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (sshbuf_len(a) != sshbuf_len(b))
		return SSH_ERR_INVALID_FORMAT;
	if (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		return SSH_ERR_INVALID_FORMAT;
	return 0;
}

static int
process_ext_session_bind(struct sshbuf* request, struct agent_connection* con)
{
	int r, sid_match, key_match;
	struct sshkey *key = NULL;
	struct sshbuf *sid = NULL, *sig = NULL;
	char *fp = NULL;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	if ((r = sshkey_froms(request, &key)) != 0 ||
	    (r = sshbuf_froms(request, &sid)) != 0 ||
	    (r = sshbuf_froms(request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(request, &fwd)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	if ((r = sshkey_verify(key, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), NULL, 0, NULL)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(key), fp);
		goto out;
	}
	/* check whether sid/key already recorded */
	for (i = 0; i < con->nsession_ids; i++) {
		if (!con->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			goto out;
		}
		sid_match = buf_equal(sid, con->session_ids[i].sid) == 0;
		key_match = sshkey_equal(key, con->session_ids[i].key);
		if (sid_match && key_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(key), fp);
			r = 0;
			goto out;
		} else if (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(key), fp);
			r = -1;
			goto out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	if (con->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		goto out;
	}
	con->session_ids = xrecallocarray(con->session_ids, con->nsession_ids,
	    con->nsession_ids + 1, sizeof(*con->session_ids));
	i = con->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(key), fp, i,
	    AGENT_MAX_SESSION_IDS);
	con->session_ids[i].key = key;
	con->session_ids[i].forwarded = fwd != 0;
	key = NULL; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	if ((con->session_ids[i].sid = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	if ((r = sshbuf_putb(con->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	sshkey_free(key);
	sshbuf_free(sid);
	sshbuf_free(sig);
	return r == 0 ? 1 : 0;
}

int
process_extension(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	int r, success = 0;
	char *name;

	debug2_f("entering");
	if ((r = sshbuf_get_cstring(request, &name, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	if (strcmp(name, "session-bind@openssh.com") == 0)
		success = process_ext_session_bind(request, con);
	else
		debug_f("unsupported extension \"%s\"", name);
	free(name);
send:
	if ((r = sshbuf_put_u32(response, 1) != 0) ||
		((r = sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0))
		fatal_fr(r, "compose");

	r = success ? 0 : -1;
	
	return r;
}

#pragma warning(pop)
