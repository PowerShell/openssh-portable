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
#include "pkcs11-cert.h"
#ifdef ENABLE_PKCS11
#include "ssh-pkcs11.h"
#endif
#include "xmalloc.h"
#include "keyagent-registry.h"
#include "keyagent-pkcs11.h"

#ifdef ENABLE_PKCS11

#pragma warning(push, 3)

extern char* allowed_providers;
extern int remote_add_provider;

extern struct sshkey *
lookup_key(const struct sshkey *k);

extern void
add_key(struct sshkey *k, char *name);

extern void
del_all_keys();

struct pkcs11_identity_change {
	char *name;
	int created;
	int had_provider;
	DWORD provider_type;
	u_char *provider;
	DWORD provider_len;
	int had_comment;
	DWORD comment_type;
	u_char *comment;
	DWORD comment_len;
};

static void
free_pkcs11_identity_change(struct pkcs11_identity_change *change)
{
	if (change == NULL)
		return;
	free(change->name);
	free(change->provider);
	free(change->comment);
	free(change);
}

static int
restore_pkcs11_identity_metadata(HKEY key,
    const struct pkcs11_identity_change *change)
{
	int r1, r2;

	r1 = restore_optional_reg_value(key, L"provider",
	    change->had_provider, change->provider_type, change->provider,
	    change->provider_len);
	r2 = restore_optional_reg_value(key, L"comment", change->had_comment,
	    change->comment_type, change->comment, change->comment_len);
	return r1 == 0 && r2 == 0 ? 0 : -1;
}

static int
pkcs11_identity_reusable(HKEY sub, const struct pkcs11_identity_change *change,
    const u_char *blob, size_t blob_len, int key_type, const char *provider)
{
	struct pkcs11_identity_entry entry;
	u_char *pub = NULL, *dflt = NULL;
	DWORD pub_type, dflt_type, pub_len, dflt_len, type, type_kind;
	DWORD type_len = sizeof(type);
	int has_pub, has_dflt, reusable = 0;

	memset(&entry, 0, sizeof(entry));
	if (read_optional_reg_value(sub, L"pub", &has_pub, &pub_type, &pub,
	    &pub_len) != 0 ||
	    read_optional_reg_value(sub, NULL, &has_dflt, &dflt_type, &dflt,
	    &dflt_len) != 0)
		goto out;
	if (has_pub && pub_type == REG_BINARY) {
		entry.pub = pub;
		entry.pub_len = pub_len;
	}
	if (has_dflt && dflt_type == REG_BINARY) {
		entry.dflt = dflt;
		entry.dflt_len = dflt_len;
	}
	if (RegQueryValueExW(sub, L"type", NULL, &type_kind, (BYTE *)&type,
	    &type_len) == ERROR_SUCCESS && type_kind == REG_DWORD &&
	    type_len == sizeof(type)) {
		entry.has_type = 1;
		entry.type = (int)type;
	}
	if (change->had_provider) {
		entry.provider = change->provider;
		entry.provider_len = change->provider_len;
	}
	if (change->had_comment) {
		entry.comment = change->comment;
		entry.comment_len = change->comment_len;
	}
	reusable = pkcs11_identity_entry_matches(&entry, blob, blob_len,
	    key_type, provider);
 out:
	free(pub);
	free(dflt);
	return reusable;
}

static int
store_pkcs11_identity(HKEY user_root, const struct sshkey *key,
    const char *provider, const char *comment,
    struct pkcs11_identity_change **changep)
{
	SECURITY_ATTRIBUTES sa = { 0, NULL, 0 };
	HKEY reg = NULL, sub = NULL;
	u_char *blob = NULL;
	size_t blob_len;
	char *thumbprint = NULL;
	struct pkcs11_identity_change *change = NULL;
	DWORD disposition = 0;
	ULONG sd_len = 0;
	int success = 0;

	if (changep == NULL || provider == NULL || comment == NULL)
		return -1;
	*changep = NULL;
	sa.nLength = sizeof(sa);
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL,
	    SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sd_len) ||
	    sshkey_to_blob(key, &blob, &blob_len) != 0 ||
	    blob_len == 0 || blob_len > MAX_MESSAGE_SIZE ||
	    (thumbprint = pkcs11_identity_name(key, blob, blob_len)) == NULL ||
	    RegCreateKeyExW(user_root, SSH_KEYS_ROOT, 0, NULL, 0,
	    KEY_WRITE | KEY_WOW64_64KEY, &sa, &reg, NULL) != ERROR_SUCCESS ||
	    RegCreateKeyExA(reg, thumbprint, 0, NULL, 0,
	    KEY_WRITE | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sa, &sub,
	    &disposition) != ERROR_SUCCESS) {
		error_f("failed to persist PKCS11 identity");
		goto out;
	}
	change = xcalloc(1, sizeof(*change));
	change->name = xstrdup(thumbprint);
	if (disposition == REG_OPENED_EXISTING_KEY) {
		if (read_optional_reg_value(sub, L"provider",
		    &change->had_provider, &change->provider_type,
		    &change->provider, &change->provider_len) != 0 ||
		    read_optional_reg_value(sub, L"comment",
		    &change->had_comment, &change->comment_type,
		    &change->comment, &change->comment_len) != 0) {
			error_f("failed to read PKCS11 identity metadata");
			goto out;
		}
		if (!pkcs11_identity_reusable(sub, change, blob, blob_len,
		    key->type, provider)) {
			error_f("refusing to replace existing identity %s "
			    "not created for this provider", thumbprint);
			goto out;
		}
		if (RegSetValueExW(sub, L"provider", 0, REG_BINARY,
		    (const BYTE *)provider, (DWORD)strlen(provider)) !=
		    ERROR_SUCCESS ||
		    RegSetValueExW(sub, L"comment", 0, REG_BINARY,
		    (const BYTE *)comment, (DWORD)strlen(comment)) !=
		    ERROR_SUCCESS) {
			error_f("failed to update PKCS11 identity metadata");
			if (restore_pkcs11_identity_metadata(sub, change) != 0)
				error_f("failed to restore PKCS11 identity metadata");
			goto out;
		}
	} else {
		change->created = 1;
		if (RegSetValueExW(sub, NULL, 0, REG_BINARY, blob,
		    (DWORD)blob_len) != ERROR_SUCCESS ||
		    RegSetValueExW(sub, L"pub", 0, REG_BINARY, blob,
		    (DWORD)blob_len) != ERROR_SUCCESS ||
		    RegSetValueExW(sub, L"type", 0, REG_DWORD,
		    (const BYTE *)&key->type, sizeof(key->type)) != ERROR_SUCCESS ||
		    RegSetValueExW(sub, L"provider", 0, REG_BINARY,
		    (const BYTE *)provider, (DWORD)strlen(provider)) !=
		    ERROR_SUCCESS ||
		    RegSetValueExW(sub, L"comment", 0, REG_BINARY,
		    (const BYTE *)comment, (DWORD)strlen(comment)) !=
		    ERROR_SUCCESS) {
			error_f("failed to persist PKCS11 identity");
			goto out;
		}
	}
	*changep = change;
	change = NULL;
	success = 1;
 out:
	if (sub != NULL) {
		RegCloseKey(sub);
		sub = NULL;
	}
	if (!success && disposition == REG_CREATED_NEW_KEY && reg != NULL &&
	    thumbprint != NULL)
		RegDeleteTreeA(reg, thumbprint);
	if (reg != NULL)
		RegCloseKey(reg);
	if (sa.lpSecurityDescriptor != NULL)
		LocalFree(sa.lpSecurityDescriptor);
	free_pkcs11_identity_change(change);
	free(thumbprint);
	free(blob);
	return success ? 0 : -1;
}

static int
store_pkcs11_provider(HKEY user_root, struct agent_connection *con,
    const char *provider, const char *pin, size_t pin_len)
{
	SECURITY_ATTRIBUTES sa = { 0, NULL, 0 };
	HKEY reg = NULL, sub = NULL;
	char *epin = NULL;
	DWORD epin_len = 0;
	DWORD disposition = 0;
	ULONG sd_len = 0;
	int success = 0;

	sa.nLength = sizeof(sa);
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL,
	    SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sd_len) ||
	    convert_blob(con, pin, (DWORD)pin_len, &epin, &epin_len, TRUE) != 0 ||
	    RegCreateKeyExW(user_root, SSH_PKCS11_PROVIDERS_ROOT, 0, NULL, 0,
	    KEY_WRITE | KEY_WOW64_64KEY, &sa, &reg, NULL) != ERROR_SUCCESS ||
	    RegCreateKeyExA(reg, provider, 0, NULL, 0,
	    KEY_WRITE | KEY_WOW64_64KEY, &sa, &sub,
	    &disposition) != ERROR_SUCCESS ||
	    RegSetValueExW(sub, L"provider", 0, REG_BINARY,
	    (const BYTE *)provider, (DWORD)strlen(provider)) != ERROR_SUCCESS ||
	    RegSetValueExW(sub, L"pin", 0, REG_BINARY, (const BYTE *)epin,
	    epin_len) != ERROR_SUCCESS) {
		error_f("failed to persist PKCS11 provider");
		goto out;
	}
	success = 1;
 out:
	if (epin != NULL) {
		SecureZeroMemory(epin, epin_len);
		free(epin);
	}
	if (sub != NULL) {
		RegCloseKey(sub);
		sub = NULL;
	}
	if (!success && disposition == REG_CREATED_NEW_KEY && reg != NULL)
		RegDeleteTreeA(reg, provider);
	if (reg != NULL)
		RegCloseKey(reg);
	if (sa.lpSecurityDescriptor != NULL)
		LocalFree(sa.lpSecurityDescriptor);
	return success ? 0 : -1;
}

static void
rollback_pkcs11_identities(HKEY user_root,
    struct pkcs11_identity_change **changes,
    size_t nidentities)
{
	HKEY reg = NULL, sub = NULL;
	size_t i;

	if (nidentities == 0)
		return;
	if (RegOpenKeyExW(user_root, SSH_KEYS_ROOT, 0,
	    DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
	    &reg) != ERROR_SUCCESS) {
		error_f("failed to open PKCS11 identities for rollback");
		return;
	}
	for (i = nidentities; i > 0; i--) {
		if (changes[i - 1]->created) {
			if (RegDeleteTreeA(reg, changes[i - 1]->name) !=
			    ERROR_SUCCESS)
				error_f("failed to roll back PKCS11 identity");
			continue;
		}
		if (RegOpenKeyExA(reg, changes[i - 1]->name, 0,
		    KEY_SET_VALUE | KEY_WOW64_64KEY, &sub) != ERROR_SUCCESS ||
		    restore_pkcs11_identity_metadata(sub, changes[i - 1]) != 0)
			error_f("failed to roll back PKCS11 identity metadata");
		if (sub != NULL) {
			RegCloseKey(sub);
			sub = NULL;
		}
	}
	RegCloseKey(reg);
}

static int
remove_pkcs11_identities(HKEY user_root, const char *provider)
{
	HKEY root = NULL, sub = NULL;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len, type, data_len;
	u_char *data = NULL;
	int index = 0, present, remove;
	LSTATUS status;

	status = RegOpenKeyExW(user_root, SSH_KEYS_ROOT, 0,
	    DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &root);
	if (status == ERROR_FILE_NOT_FOUND)
		return 0;
	if (status != ERROR_SUCCESS)
		return -1;
	for (;;) {
		sub_name_len = MAX_KEY_LENGTH;
		status = RegEnumKeyExW(root, index, sub_name, &sub_name_len,
		    NULL, NULL, NULL, NULL);
		if (status == ERROR_NO_MORE_ITEMS)
			break;
		if (status != ERROR_SUCCESS) {
			index++;
			continue;
		}
		if (RegOpenKeyExW(root, sub_name, 0,
		    KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sub) != ERROR_SUCCESS) {
			index++;
			continue;
		}
		free(data);
		data = NULL;
		if (read_optional_reg_value(sub, L"provider", &present, &type,
		    &data, &data_len) != 0 ||
		    (!present && read_optional_reg_value(sub, L"comment",
		    &present, &type, &data, &data_len) != 0)) {
			RegCloseKey(sub);
			sub = NULL;
			index++;
			continue;
		}
		remove = present && pkcs11_provider_equal(data, data_len, provider);
		RegCloseKey(sub);
		sub = NULL;
		if (remove) {
			if (RegDeleteTreeW(root, sub_name) != ERROR_SUCCESS) {
				RegCloseKey(root);
				free(data);
				return -1;
			}
		} else
			index++;
	}
	RegCloseKey(root);
	free(data);
	return 0;
}

static int
load_pkcs11_identities(HKEY user_root, const char *provider,
    struct sshkey **token_keys, int nkeys)
{
	HKEY root = NULL, sub = NULL;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len, blob_len, comment_len, association_len;
	u_char *blob = NULL;
	char *comment = NULL, *association = NULL;
	struct sshkey *registered = NULL, *cert = NULL;
	u_char *plain_added = NULL;
	int i, index = 0, legacy, loaded = 0;
	LSTATUS status;

	if (nkeys > 0)
		plain_added = xcalloc((size_t)nkeys, sizeof(*plain_added));
	status = RegOpenKeyExW(user_root, SSH_KEYS_ROOT, 0,
	    KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &root);
	if (status == ERROR_FILE_NOT_FOUND)
		goto out;
	if (status != ERROR_SUCCESS) {
		error_f("failed to open persisted identities: %ld", status);
		loaded = -1;
		goto out;
	}
	for (;;) {
		sub_name_len = MAX_KEY_LENGTH;
		if (sub != NULL) {
			RegCloseKey(sub);
			sub = NULL;
		}
		status = RegEnumKeyExW(root, index++, sub_name, &sub_name_len,
		    NULL, NULL, NULL, NULL);
		if (status == ERROR_NO_MORE_ITEMS)
			break;
		if (status != ERROR_SUCCESS)
			continue;
		if (RegOpenKeyExW(root, sub_name, 0,
		    KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sub) != ERROR_SUCCESS ||
		    RegQueryValueExW(sub, L"pub", NULL, NULL, NULL,
		    &blob_len) != ERROR_SUCCESS ||
		    RegQueryValueExW(sub, L"comment", NULL, NULL, NULL,
		    &comment_len) != ERROR_SUCCESS ||
		    blob_len == 0 || blob_len > MAX_MESSAGE_SIZE ||
		    comment_len > MAX_MESSAGE_SIZE)
			continue;
		status = RegQueryValueExW(sub, L"provider", NULL, NULL, NULL,
		    &association_len);
		if (status == ERROR_FILE_NOT_FOUND) {
			legacy = 1;
			association_len = comment_len;
		} else if (status == ERROR_SUCCESS &&
		    association_len <= MAX_MESSAGE_SIZE)
			legacy = 0;
		else
			continue;
		free(blob);
		free(comment);
		free(association);
		blob = xmalloc(blob_len);
		comment = xmalloc((size_t)comment_len + 1);
		association = xmalloc((size_t)association_len + 1);
		if (RegQueryValueExW(sub, L"pub", NULL, NULL, blob,
		    &blob_len) != ERROR_SUCCESS ||
		    RegQueryValueExW(sub, L"comment", NULL, NULL,
		    (BYTE *)comment, &comment_len) != ERROR_SUCCESS ||
		    (!legacy && RegQueryValueExW(sub, L"provider", NULL, NULL,
		    (BYTE *)association, &association_len) != ERROR_SUCCESS))
			continue;
		comment[comment_len] = '\0';
		if (legacy)
			memcpy(association, comment, comment_len);
		association[association_len] = '\0';
		if (!pkcs11_provider_equal((u_char *)association, association_len,
		    provider))
			continue;
		sshkey_free(registered);
		registered = NULL;
		if (sshkey_from_blob(blob, blob_len, &registered) != 0)
			continue;
		for (i = 0; i < nkeys; i++) {
			if (token_keys[i] == NULL)
				continue;
			if (sshkey_is_cert(registered)) {
				if (!sshkey_equal_public(token_keys[i], registered))
					continue;
				if (pkcs11_make_cert(token_keys[i], registered,
				    &cert) != 0)
					continue;
				add_key(cert, (char *)provider);
				cert = NULL;
				loaded++;
				break;
			}
			if (!plain_added[i] &&
			    sshkey_equal(token_keys[i], registered)) {
				plain_added[i] = 1;
				break;
			}
		}
	}
	for (i = 0; i < nkeys; i++) {
		if (!plain_added[i] || token_keys[i] == NULL)
			continue;
		add_key(token_keys[i], (char *)provider);
		token_keys[i] = NULL;
		loaded++;
	}
 out:
	sshkey_free(cert);
	sshkey_free(registered);
	free(plain_added);
	free(association);
	free(comment);
	free(blob);
	if (sub != NULL)
		RegCloseKey(sub);
	if (root != NULL)
		RegCloseKey(root);
	return loaded;
}

static void
free_pkcs11_sign_provider(char **providerp, char **pinp, DWORD pin_len,
    char **epinp, DWORD epin_len, struct sshkey ***keysp, int nkeys)
{
	int i;

	if (*keysp != NULL) {
		for (i = 0; i < nkeys; i++)
			sshkey_free((*keysp)[i]);
		free(*keysp);
		*keysp = NULL;
	}
	free(*providerp);
	*providerp = NULL;
	if (*pinp != NULL) {
		SecureZeroMemory(*pinp, pin_len);
		free(*pinp);
		*pinp = NULL;
	}
	if (*epinp != NULL) {
		SecureZeroMemory(*epinp, epin_len);
		free(*epinp);
		*epinp = NULL;
	}
}

struct sshkey *
keyagent_pkcs11_lookup_key(const struct sshkey *key)
{
	return lookup_key(key);
}

int
keyagent_pkcs11_reload_providers(struct agent_connection *con)
{
	int count = 0, index = 0, loaded = 0, ret = -1;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len = MAX_KEY_LENGTH;
	DWORD pin_len = 0, epin_len = 0, provider_len = 0;
	DWORD epin_alloc_len = 0;
	char *pin = NULL, *npin = NULL, *epin = NULL, *provider = NULL;
	HKEY root = 0, sub = 0, user_root = 0;
	struct sshkey **keys = NULL;
	SECURITY_ATTRIBUTES sa = { 0, NULL, 0 };
	ULONG sd_len = 0;

	pkcs11_init(0);

	sa.nLength = sizeof(sa);
	if ((!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sd_len)) ||
		get_user_root(con, &user_root) != 0 ||
		RegCreateKeyExW(user_root, SSH_PKCS11_PROVIDERS_ROOT, 0, 0, 0, KEY_WRITE | STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &sa, &root, NULL) != 0) {
		goto out;
	}

	while (1) {
		sub_name_len = MAX_KEY_LENGTH;
		pin_len = epin_len = provider_len = 0;
		epin_alloc_len = 0;
		if (sub) {
			RegCloseKey(sub);
			sub = NULL;
		}
		if (RegEnumKeyExW(root, index++, sub_name, &sub_name_len, NULL, NULL, NULL, NULL) == 0) {
			if (RegOpenKeyExW(root, sub_name, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sub) == 0 &&
				RegQueryValueExW(sub, L"provider", 0, NULL, NULL, &provider_len) == 0 &&
				RegQueryValueExW(sub, L"pin", 0, NULL, NULL, &epin_len) == 0) {
				if (provider_len == 0 || provider_len >= PATH_MAX ||
				    epin_len == 0 || epin_len > MAX_MESSAGE_SIZE)
					continue;
				epin_alloc_len = epin_len;
				if ((epin = malloc(epin_alloc_len + 1)) == NULL ||
					(provider = malloc(provider_len + 1)) == NULL ||
					RegQueryValueExW(sub, L"provider", 0, NULL, provider, &provider_len) != 0 ||
					RegQueryValueExW(sub, L"pin", 0, NULL, epin, &epin_len) != 0) {
					free_pkcs11_sign_provider(&provider, &pin, pin_len,
					    &epin, epin_alloc_len, &keys, count);
					continue;
				}
				provider[provider_len] = '\0';
				epin[epin_len] = '\0';
				if (convert_blob(con, epin, epin_len, &pin, &pin_len, 0) != 0 ||
					(npin = realloc(pin, pin_len + 1)) == NULL) {
					free_pkcs11_sign_provider(&provider, &pin, pin_len,
					    &epin, epin_alloc_len, &keys, count);
					continue;
				}
				pin = npin;
				pin[pin_len] = '\0';
				count = pkcs11_add_provider(provider, pin, &keys, NULL);
				if (count <= 0) {
					free_pkcs11_sign_provider(&provider, &pin, pin_len,
					    &epin, epin_alloc_len, &keys, count);
					continue;
				}
				loaded = load_pkcs11_identities(user_root, provider,
				    keys, count);
				free_pkcs11_sign_provider(&provider, &pin, pin_len,
				    &epin, epin_alloc_len, &keys, count);
				if (loaded < 0)
					goto out;
			}
		}
		else
			break;
	}
	ret = 0;
out:
	free_pkcs11_sign_provider(&provider, &pin, pin_len, &epin, epin_alloc_len,
	    &keys, count);
	if (sa.lpSecurityDescriptor != NULL)
		LocalFree(sa.lpSecurityDescriptor);
	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	if (sub)
		RegCloseKey(sub);
	return ret;
}

void
keyagent_pkcs11_release(void)
{
	del_all_keys();
	pkcs11_terminate();
}

LSTATUS
keyagent_pkcs11_delete_cert_identity(HKEY root, const struct sshkey *key,
    const u_char *blob, size_t blob_len)
{
	char *name;
	LSTATUS status;

	if ((name = pkcs11_identity_name(key, blob, blob_len)) == NULL)
		return ERROR_INVALID_DATA;
	status = delete_matching_identity(root, name, blob, blob_len);
	free(name);
	return status;
}

/*
 * Resolve provider to the canonical path used as Registry identity, without
 * the leading slash realpath() puts in front of a Windows drive letter.
 * canonical must hold PATH_MAX bytes.
 */
static int
canonicalize_provider_path(const char *provider, char *canonical,
    const char *op)
{
	if (realpath(provider, canonical) == NULL) {
		error("failed PKCS#11 %s of \"%.100s\": realpath: %s",
		    op, provider, strerror(errno));
		return -1;
	}
	if (canonical[0] == '/')
		memmove(canonical, canonical + 1, strlen(canonical));
	return 0;
}

/*
 * Persist key as identity of provider and remember how to roll it back
 * in *changesp, which is grown by one entry on success.
 */
static int
store_and_track_pkcs11_identity(HKEY user_root, const struct sshkey *key,
    const char *provider, const char *comment,
    struct pkcs11_identity_change ***changesp, size_t *nchangesp)
{
	struct pkcs11_identity_change *change = NULL;

	if (store_pkcs11_identity(user_root, key, provider, comment,
	    &change) != 0)
		return -1;
	*changesp = xrecallocarray(*changesp, *nchangesp, *nchangesp + 1,
	    sizeof(**changesp));
	(*changesp)[(*nchangesp)++] = change;
	return 0;
}

int
process_add_smartcard_key(struct sshbuf *request, struct sshbuf *response,
    struct agent_connection *con)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX] = { 0 };
	char allowed_provider[PATH_MAX], **labels = NULL;
	const char *comment;
	int i, j, count = 0, r = 0, request_invalid = 0, success = 0;
	int cert_only = 0, identities_stored = 0;
	struct sshkey **keys = NULL, **certs = NULL, *cert = NULL;
	struct pkcs11_identity_change **identity_changes = NULL;
	size_t k, pin_len = 0, ncerts = 0, nidentity_changes = 0;
	HKEY user_root = NULL;

	pkcs11_init(0);

	if ((r = sshbuf_get_cstring(request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(request, &pin, &pin_len)) != 0 ||
	    pin_len > 256) {
		error("add smartcard request is invalid");
		request_invalid = 1;
		goto done;
	}
	if (sshbuf_len(request) != 0 &&
	    parse_pkcs11_add_constraints(request, &cert_only, &certs,
	    &ncerts) != 0) {
		error("add smartcard constraints are invalid");
		request_invalid = 1;
		goto done;
	}

	if (con->nsession_ids != 0 && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		goto done;
	}

	if (canonicalize_provider_path(provider, canonical_provider,
	    "add") != 0) {
		request_invalid = 1;
		goto done;
	}

	strcpy_s(allowed_provider, sizeof(allowed_provider), canonical_provider);
	for (i = 0; allowed_provider[i] != '\0'; i++) {
		if (allowed_provider[i] == '/')
			allowed_provider[i] = '\\';
	}
	to_lower_case(allowed_provider);
	verbose("provider realpath: \"%.100s\"", canonical_provider);
	verbose("allowed provider paths: \"%.100s\"", allowed_providers);
	if (match_pattern_list(allowed_provider, allowed_providers, 1) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		goto done;
	}

	count = pkcs11_add_provider(canonical_provider, pin, &keys, &labels);
	if (count <= 0) {
		error_f("failed to load provider keys: count:%d", count);
		goto done;
	}

	if (get_user_root(con, &user_root) != 0)
		goto done;

	for (i = 0; i < count; i++) {
		comment = pkcs11_identity_comment(canonical_provider, labels[i]);
		for (j = 0; j < (int)ncerts; j++) {
			if (!sshkey_is_cert(certs[j]) ||
			    !sshkey_equal_public(keys[i], certs[j]))
				continue;
			if (pkcs11_make_cert(keys[i], certs[j], &cert) != 0)
				continue;
			if (store_and_track_pkcs11_identity(user_root, cert,
			    canonical_provider, comment, &identity_changes,
			    &nidentity_changes) != 0)
				goto done;
			sshkey_free(cert);
			cert = NULL;
			identities_stored++;
		}
		if (cert_only)
			continue;
		if (store_and_track_pkcs11_identity(user_root, keys[i],
		    canonical_provider, comment, &identity_changes,
		    &nidentity_changes) != 0)
			goto done;
		identities_stored++;
	}

	if (identities_stored == 0 || store_pkcs11_provider(user_root, con,
	    canonical_provider, pin, pin_len) != 0)
		goto done;
	debug("added PKCS11 provider and identities to store");
	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;

	if (!success && user_root != NULL)
		rollback_pkcs11_identities(user_root, identity_changes,
		    nidentity_changes);

	sshkey_free(cert);
	for (k = 0; k < nidentity_changes; k++)
		free_pkcs11_identity_change(identity_changes[k]);
	free(identity_changes);
	for (i = 0; i < count; i++)
		sshkey_free(keys[i]);
	free(keys);
	for (i = 0; i < count; i++)
		free(labels[i]);
	free(labels);
	free_pkcs11_certs(certs, ncerts);
	pkcs11_terminate();
	free(provider);
	if (pin) {
		SecureZeroMemory(pin, (DWORD)pin_len);
		free(pin);
	}
	if (user_root)
		RegCloseKey(user_root);
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

	if (canonicalize_provider_path(provider, canonical_provider,
	    "remove") != 0) {
		request_invalid = 1;
		goto done;
	}

	if (get_user_root(con, &user_root) != 0 ||
		!is_reg_sub_key_exists(user_root, SSH_PKCS11_PROVIDERS_ROOT, canonical_provider))
		goto done;

	if (remove_pkcs11_identities(user_root, canonical_provider) != 0 ||
	    remove_matching_subkeys_from_registry(user_root,
	    SSH_PKCS11_PROVIDERS_ROOT, L"provider", canonical_provider) != 0) {
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

#pragma warning(pop)

#endif /* ENABLE_PKCS11 */
