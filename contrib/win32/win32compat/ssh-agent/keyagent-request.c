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
#include "match.h"
#include <sddl.h>
#ifdef ENABLE_PKCS11
#include "ssh-pkcs11.h"
#endif
#include "xmalloc.h"

#pragma warning(push, 3)

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME_LENGTH 16383
#define MAX_VALUE_DATA_LENGTH 2048

extern char* allowed_providers;
extern int remote_add_provider;

/* 
 * get registry root where keys are stored 
 * user keys are stored in user's hive
 * while system keys (host keys) in HKLM
 */

extern struct sshkey *
lookup_key(const struct sshkey *k);

extern void
add_key(struct sshkey *k, char *name);

extern void
del_all_keys();

static int
get_user_root(struct agent_connection* con, HKEY *root)
{
	int r = 0;
	LONG ret;
	*root = HKEY_LOCAL_MACHINE;
	
	if (con->client_type <= ADMIN_USER) {
		if (ImpersonateLoggedOnUser(con->client_impersonation_token) == FALSE)
			return -1;
		*root = NULL;
		/* 
		 * TODO - check that user profile is loaded, 
		 * otherwise, this will return default profile 
		 */
		if ((ret = RegOpenCurrentUser(KEY_ALL_ACCESS, root)) != ERROR_SUCCESS) {
			debug("unable to open user's registry hive, ERROR - %d", ret);
			r = -1;
		}
			
		RevertToSelf();
	}
	return r;
}

static int
convert_blob(struct agent_connection* con, const char *blob, DWORD blen, char **eblob, DWORD *eblen, int encrypt) {
	int success = 0;
	DATA_BLOB in, out;
	errno_t r = 0;

	if (con->client_type <= ADMIN_USER)
		if (ImpersonateLoggedOnUser(con->client_impersonation_token) == FALSE)
			return -1;

	in.cbData = blen;
	in.pbData = (char*)blob;
	out.cbData = 0;
	out.pbData = NULL;

	if (encrypt) {
		if (!CryptProtectData(&in, NULL, NULL, 0, NULL, 0, &out)) {
			debug("cannot encrypt data");
			goto done;
		}
	} else {
		if (!CryptUnprotectData(&in, NULL, NULL, 0, NULL, 0, &out)) {
			debug("cannot decrypt data");
			goto done;
		}
	}

	*eblob = malloc(out.cbData);
	if (*eblob == NULL) 
		goto done;

	if((r = memcpy_s(*eblob, out.cbData, out.pbData, out.cbData)) != 0) {
		debug("memcpy_s failed with error: %d.", r);
		goto done;
	}
	*eblen = out.cbData;
	success = 1;
done:
	if (out.pbData)
		LocalFree(out.pbData);
	if (con->client_type <= ADMIN_USER)
		RevertToSelf();
	return success? 0: -1;
}

/*
 * in user_root sub tree under key_name key
 * remove all sub keys with value name value_name_to_remove
 * and value data value_data_to_remove
 */
static int
remove_matching_subkeys_from_registry(HKEY user_root, wchar_t const* key_name, wchar_t const* value_name_to_remove, char const* value_data_to_remove) {
	int index = 0, success = 0;
	DWORD data_len;
	HKEY root = 0, sub = 0;
	char *data = NULL;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len = MAX_KEY_LENGTH;
	LSTATUS retCode;

	if (RegOpenKeyExW(user_root, key_name, 0, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &root) != 0) {
		goto done;
	}

	while (1) {
		sub_name_len = MAX_KEY_LENGTH;
		if (sub) {
			RegCloseKey(sub);
			sub = NULL;
		}
		if ((retCode = RegEnumKeyExW(root, index++, sub_name, &sub_name_len, NULL, NULL, NULL, NULL)) == 0) {
			if (RegOpenKeyExW(root, sub_name, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sub) == 0 &&
				RegQueryValueExW(sub, value_name_to_remove, 0, NULL, NULL, &data_len) == 0 &&
				data_len <= MAX_VALUE_DATA_LENGTH) {

				if (data)
					free(data);
				data = NULL;

				if ((data = malloc(data_len + 1)) == NULL ||
					RegQueryValueExW(sub, value_name_to_remove, 0, NULL, data, &data_len) != 0)
					goto done;
				data[data_len] = '\0';
				if (strncmp(data, value_data_to_remove, data_len) == 0) {
					if (RegDeleteTreeW(root, sub_name) != 0)
						goto done;
					--index;
				}
			}
		}
		else {
			if (retCode == ERROR_NO_MORE_ITEMS)
				success = 1;
			break;
		}
	}
done:
	if (data)
		free(data);
	if (root)
		RegCloseKey(root);
	if (sub)
		RegCloseKey(sub);
	return success ? 0 : -1;
}

/*
 * in user_root sub tree under key_name key
 * check whether sub_key_name sub key exists
 */
static int
is_reg_sub_key_exists(HKEY user_root, wchar_t const* key_name, char const* sub_key_name) {
	int rv = 0;
	HKEY root = 0, sub = 0;

	if (RegOpenKeyExW(user_root, key_name, 0, STANDARD_RIGHTS_READ | KEY_WOW64_64KEY, &root) != 0 ||
		RegOpenKeyExA(root, sub_key_name, 0, STANDARD_RIGHTS_READ | KEY_WOW64_64KEY, &sub) != 0 || !sub) {
		rv = 0;
		goto done;
	}

	rv = 1;
done:
	if (root)
		RegCloseKey(root);
	return rv;
}

#define REG_KEY_SDDL L"D:P(A;; GA;;; SY)(A;; GA;;; BA)"

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
	char *thumbprint = NULL, *comment;
	const char *blob;
	char* eblob = NULL;
	HKEY reg = 0, sub = 0, user_root = 0;
	SECURITY_ATTRIBUTES sa;

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
	if ((!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sa.nLength)) ||
	    sshkey_to_blob(key, &pubkey_blob, &pubkey_blob_len) != 0 ||
	    convert_blob(con, blob, blob_len, &eblob, &eblob_len, 1) != 0 ||
	    ((thumbprint = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL) ||
	    get_user_root(con, &user_root) != 0 ||
	    RegCreateKeyExW(user_root, SSH_KEYS_ROOT, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &reg, NULL) != 0 ||
	    RegCreateKeyExA(reg, thumbprint, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &sub, NULL) != 0 ||
	    RegSetValueExW(sub, NULL, 0, REG_BINARY, eblob, eblob_len) != 0 ||
	    RegSetValueExW(sub, L"pub", 0, REG_BINARY, pubkey_blob, (DWORD)pubkey_blob_len) != 0 ||
	    RegSetValueExW(sub, L"type", 0, REG_DWORD, (BYTE*)&key->type, 4) != 0 ||
	    RegSetValueExW(sub, L"comment", 0, REG_BINARY, comment, (DWORD)comment_len) != 0 ) {
		error("failed to add key to store");
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
	if ((success == 0) && reg && thumbprint)
		RegDeleteKeyExA(reg, thumbprint, KEY_WOW64_64KEY, 0);

	if (eblob)
		free(eblob);
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
#ifdef ENABLE_PKCS11
	int is_pkcs11_key = 0;
#endif /* ENABLE_PKCS11 */

	*sig = NULL;
	*siglen = 0;

#ifdef ENABLE_PKCS11
	if ((prikey = lookup_key(pubkey)) == NULL) {
#endif /* ENABLE_PKCS11 */
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
#ifdef ENABLE_PKCS11
	}
	else
		is_pkcs11_key = 1;
#endif /* ENABLE_PKCS11 */
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
#ifdef ENABLE_PKCS11
	if (!is_pkcs11_key)
#endif /* ENABLE_PKCS11 */
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

#ifdef ENABLE_PKCS11
	int i, count = 0, index = 0;;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len = MAX_KEY_LENGTH;
	DWORD pin_len, epin_len, provider_len;
	char *pin = NULL, *npin = NULL, *epin = NULL, *provider = NULL;
	HKEY root = 0, sub = 0, user_root = 0;
	struct sshkey **keys = NULL;
	SECURITY_ATTRIBUTES sa = { 0, NULL, 0 };

	pkcs11_init(0);

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);
	if ((!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sa.nLength)) ||
		get_user_root(con, &user_root) != 0 ||
		RegCreateKeyExW(user_root, SSH_PKCS11_PROVIDERS_ROOT, 0, 0, 0, KEY_WRITE | STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &sa, &root, NULL) != 0) {
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
				RegQueryValueExW(sub, L"provider", 0, NULL, NULL, &provider_len) == 0 &&
				RegQueryValueExW(sub, L"pin", 0, NULL, NULL, &epin_len) == 0) {
				if ((epin = malloc(epin_len + 1)) == NULL ||
					(provider = malloc(provider_len + 1)) == NULL ||
					RegQueryValueExW(sub, L"provider", 0, NULL, provider, &provider_len) != 0 ||
					RegQueryValueExW(sub, L"pin", 0, NULL, epin, &epin_len) != 0)
					goto done;
				provider[provider_len] = '\0';
				epin[epin_len] = '\0';
				if (convert_blob(con, epin, epin_len, &pin, &pin_len, 0) != 0 ||
					(npin = realloc(pin, pin_len + 1)) == NULL) {
					goto done;
				}
				pin = npin;
				pin[pin_len] = '\0';
				count = pkcs11_add_provider(provider, pin, &keys, NULL);
				for (i = 0; i < count; i++) {
					add_key(keys[i], provider);
				}
				free(keys);
				if (provider)
					free(provider);
				if (pin) {
					SecureZeroMemory(pin, (DWORD)pin_len);
					free(pin);
				}
				if (epin) {
					SecureZeroMemory(epin, (DWORD)epin_len);
					free(epin);
				}
				provider = NULL;
				pin = NULL;
				epin = NULL;
			}
		}
		else
			break;
	}
#endif /* ENABLE_PKCS11 */

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
#ifdef ENABLE_PKCS11
	del_all_keys();
	pkcs11_terminate();
	if (provider)
		free(provider);
	if (pin) {
		SecureZeroMemory(pin, (DWORD)pin_len);
		free(pin);
	}
	if (epin) {
		SecureZeroMemory(epin, (DWORD)epin_len);
		free(epin);
	}
	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	if (sub)
		RegCloseKey(sub);
#endif /* ENABLE_PKCS11 */
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

	if (sshbuf_get_string_direct(request, &blob, &blen) != 0 ||
	    sshkey_from_blob(blob, blen, &key) != 0) { 
		request_invalid = 1;
		goto done;
	}

	if ((thumbprint = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL ||
	    get_user_root(con, &user_root) != 0 ||
	    RegOpenKeyExW(user_root, SSH_KEYS_ROOT, 0,
		DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &root) != 0 ||
	    RegDeleteTreeA(root, thumbprint) != 0)
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

#ifdef ENABLE_PKCS11
int process_add_smartcard_key(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int i, count = 0, r = 0, request_invalid = 0, success = 0;
	struct sshkey **keys = NULL;
	struct sshkey* key = NULL;
	size_t pubkey_blob_len, provider_len, pin_len, epin_len;
	u_char *pubkey_blob = NULL;
	char *thumbprint = NULL;
	char *epin = NULL;
	HKEY reg = 0, sub = 0, user_root = 0;
	SECURITY_ATTRIBUTES sa = { 0, NULL, 0 };

	pkcs11_init(0);

	if ((r = sshbuf_get_cstring(request, &provider, &provider_len)) != 0 ||
		(r = sshbuf_get_cstring(request, &pin, &pin_len)) != 0 ||
		pin_len > 256) {
		error("add smartcard request is invalid");
		request_invalid = 1;
		goto done;
	}

	if (con->nsession_ids != 0 && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		goto done;
	}
	
	if (realpath(provider, canonical_provider) == NULL) {
		error("failed PKCS#11 add of \"%.100s\": realpath: %s",
			provider, strerror(errno));
		request_invalid = 1;
		goto done;
	}

	if (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
			"provider not allowed", canonical_provider);
		goto done;
	}

	// Remove 'drive root' if exists
	if (canonical_provider[0] == '/')
		memmove(canonical_provider, canonical_provider + 1, strlen(canonical_provider));

	count = pkcs11_add_provider(canonical_provider, pin, &keys, NULL);
	if (count <= 0) {
		error_f("failed to add key to store. count:%d", count);
		goto done;
	}

	// If HKCU registry already has the provider then remove the provider and associated keys.
	// This allows customers to add new keys.
	if (get_user_root(con, &user_root) != 0 ||
		is_reg_sub_key_exists(user_root, SSH_PKCS11_PROVIDERS_ROOT, canonical_provider)) {
		remove_matching_subkeys_from_registry(user_root, SSH_KEYS_ROOT, L"comment", canonical_provider);
		remove_matching_subkeys_from_registry(user_root, SSH_PKCS11_PROVIDERS_ROOT, L"provider", canonical_provider);
	}

	for (i = 0; i < count; i++) {
		key = keys[i];
		if (sa.lpSecurityDescriptor)
			LocalFree(sa.lpSecurityDescriptor);
		if (reg) {
			RegCloseKey(reg);
			reg = NULL;
		}
		if (sub) {
			RegCloseKey(sub);
			sub = NULL;
		}
		memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
		sa.nLength = sizeof(sa);
		if ((!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sa.nLength)) ||
			sshkey_to_blob(key, &pubkey_blob, &pubkey_blob_len) != 0 ||
			((thumbprint = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL) ||
			RegCreateKeyExW(user_root, SSH_KEYS_ROOT, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &reg, NULL) != 0 ||
			RegCreateKeyExA(reg, thumbprint, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &sub, NULL) != 0 ||
			RegSetValueExW(sub, NULL, 0, REG_BINARY, pubkey_blob, (DWORD)pubkey_blob_len) != 0 ||
			RegSetValueExW(sub, L"pub", 0, REG_BINARY, pubkey_blob, (DWORD)pubkey_blob_len) != 0 ||
			RegSetValueExW(sub, L"type", 0, REG_DWORD, (BYTE*)&key->type, 4) != 0 ||
			RegSetValueExW(sub, L"comment", 0, REG_BINARY, canonical_provider, (DWORD)strlen(canonical_provider)) != 0) {
			error_f("failed to add key to store");
			goto done;
		}
	}

	debug("added smartcard keys to store");

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);
	if ((!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sa.nLength)) ||
		convert_blob(con, pin, (DWORD)pin_len, &epin, (DWORD*)&epin_len, 1) != 0 ||
		RegCreateKeyExW(user_root, SSH_PKCS11_PROVIDERS_ROOT, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &reg, NULL) != 0 ||
		RegCreateKeyExA(reg, canonical_provider, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &sub, NULL) != 0 ||
		RegSetValueExW(sub, L"provider", 0, REG_BINARY, canonical_provider, (DWORD)strlen(canonical_provider)) != 0 ||
		RegSetValueExW(sub, L"pin", 0, REG_BINARY, epin, (DWORD)epin_len) != 0) {
		error("failed to add pkcs11 provider to store");
		goto done;
	}

	debug("added pkcs11 provider to store");
	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;

	/* delete created reg keys if not succeeded*/
	if ((success == 0) && reg) {
		if (thumbprint)
			RegDeleteKeyExA(reg, thumbprint, KEY_WOW64_64KEY, 0);
		if (canonical_provider)
			RegDeleteKeyExA(reg, canonical_provider, KEY_WOW64_64KEY, 0);
	}

	pkcs11_terminate();

	if (sa.lpSecurityDescriptor)
		LocalFree(sa.lpSecurityDescriptor);
	for (i = 0; i < count; i++)
		sshkey_free(keys[i]);
	if (keys)
		free(keys);
	if (thumbprint)
		free(thumbprint);
	if (pubkey_blob)
		free(pubkey_blob);
	if (provider)
		free(provider);
	if (allowed_providers)
		free(allowed_providers);
	if (pin) {
		SecureZeroMemory(pin, (DWORD)pin_len);
		free(pin);
	}
	if (epin) {
		SecureZeroMemory(epin, (DWORD)epin_len);
		free(epin);
	}
	if (user_root)
		RegCloseKey(user_root);
	if (reg)
		RegCloseKey(reg);
	if (sub)
		RegCloseKey(sub);
	return r;
}

int process_remove_smartcard_key(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r = 0, request_invalid = 0, success = 0, index = 0;
	HKEY user_root = 0;

	if ((r = sshbuf_get_cstring(request, &provider, NULL)) != 0 ||
		(r = sshbuf_get_cstring(request, &pin, NULL)) != 0) {
		error("remove smartcard request is invalid");
		request_invalid = 1;
		goto done;
	}

	if (realpath(provider, canonical_provider) == NULL) {
		error("failed PKCS#11 add of \"%.100s\": realpath: %s",
			provider, strerror(errno));
		request_invalid = 1;
		goto done;
	}

	// Remove 'drive root' if exists
	if (canonical_provider[0] == '/')
		memmove(canonical_provider, canonical_provider + 1, strlen(canonical_provider));

	if (get_user_root(con, &user_root) != 0 ||
		!is_reg_sub_key_exists(user_root, SSH_PKCS11_PROVIDERS_ROOT, canonical_provider))
		goto done;

	if (remove_matching_subkeys_from_registry(user_root, SSH_KEYS_ROOT, L"comment", canonical_provider) != 0 ||
		remove_matching_subkeys_from_registry(user_root, SSH_PKCS11_PROVIDERS_ROOT, L"provider", canonical_provider) != 0) {
		goto done;
	}

	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;
	if (provider)
		free(provider);
	if (pin)
		free(pin);
	if (user_root)
		RegCloseKey(user_root);
	return r;
}
#endif /* ENABLE_PKCS11 */

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

#if 0
int process_keyagent_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	u_char type;

	if (sshbuf_get_u8(request, &type) != 0)
		return -1;
	debug2("process key agent request type %d", type);

	switch (type) {
	case SSH2_AGENTC_ADD_IDENTITY:
		return process_add_identity(request, response, con);
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		return process_request_identities(request, response, con);
	case SSH2_AGENTC_SIGN_REQUEST:
		return process_sign_request(request, response, con);
	case SSH2_AGENTC_REMOVE_IDENTITY:
		return process_remove_key(request, response, con);
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		return process_remove_all(request, response, con);
#ifdef ENABLE_PKCS11
	case SSH_AGENTC_ADD_SMARTCARD_KEY:
		return process_add_smartcard_key(request, response, con);
	case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		return process_add_smartcard_key(request, response, con);
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		return process_remove_smartcard_key(request, response, con);
		break;
#endif /* ENABLE_PKCS11 */
	default:
		debug("unknown key agent request %d", type);
		return -1;		
	}
}
#endif

#pragma warning(pop)
