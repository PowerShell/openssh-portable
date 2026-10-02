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
#include "config.h"
#include "pkcs11-cert.h"
#include "xmalloc.h"
#include "keyagent-registry.h"

#pragma warning(push, 3)

/*
 * get registry root where keys are stored
 * user keys are stored in user's hive
 * while system keys (host keys) in HKLM
 */
int
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

int
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

int
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
				if (pkcs11_provider_equal((u_char *)data, data_len,
				    value_data_to_remove)) {
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

int
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

int
read_optional_reg_value(HKEY key, const wchar_t *name, int *presentp,
    DWORD *typep, u_char **datap, DWORD *lenp)
{
	LSTATUS status;

	*presentp = 0;
	*datap = NULL;
	*lenp = 0;
	status = RegQueryValueExW(key, name, NULL, typep, NULL, lenp);
	if (status == ERROR_FILE_NOT_FOUND)
		return 0;
	if (status != ERROR_SUCCESS || *lenp > MAX_MESSAGE_SIZE)
		return -1;
	*datap = xmalloc(*lenp == 0 ? 1 : *lenp);
	if (RegQueryValueExW(key, name, NULL, typep, *datap,
	    lenp) != ERROR_SUCCESS) {
		free(*datap);
		*datap = NULL;
		return -1;
	}
	*presentp = 1;
	return 0;
}

int
restore_optional_reg_value(HKEY key, const wchar_t *name, int present,
    DWORD type, const u_char *data, DWORD len)
{
	LSTATUS status;

	if (present)
		return RegSetValueExW(key, name, 0, type, data, len) ==
		    ERROR_SUCCESS ? 0 : -1;
	status = RegDeleteValueW(key, name);
	return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND ? 0 : -1;
}

/*
 * delete the identity sub key name below root, but only if its stored
 * public key blob matches blob
 */
LSTATUS
delete_matching_identity(HKEY root, const char *name, const u_char *blob,
    size_t blob_len)
{
	HKEY sub = NULL;
	u_char *stored_blob = NULL;
	DWORD stored_blob_len = 0;
	LSTATUS status;

	status = RegOpenKeyExA(root, name, 0,
	    KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sub);
	if (status != ERROR_SUCCESS)
		return status;
	status = RegQueryValueExW(sub, L"pub", NULL, NULL, NULL,
	    &stored_blob_len);
	if (status != ERROR_SUCCESS)
		goto out;
	if (stored_blob_len > MAX_MESSAGE_SIZE) {
		status = ERROR_INVALID_DATA;
		goto out;
	}
	stored_blob = xmalloc(stored_blob_len == 0 ? 1 : stored_blob_len);
	status = RegQueryValueExW(sub, L"pub", NULL, NULL, stored_blob,
	    &stored_blob_len);
	if (status != ERROR_SUCCESS)
		goto out;
	if (stored_blob_len != blob_len ||
	    memcmp(stored_blob, blob, blob_len) != 0) {
		status = ERROR_FILE_NOT_FOUND;
		goto out;
	}
	RegCloseKey(sub);
	sub = NULL;
	status = RegDeleteTreeA(root, name);
 out:
	free(stored_blob);
	if (sub != NULL)
		RegCloseKey(sub);
	return status;
}

int
read_agent_identity(HKEY sub, struct agent_connection *con,
    struct sshkey **keyp, char **providerp)
{
	u_char *data[5] = { NULL };
	DWORD len[5] = { 0 }, kind[5] = { 0 }, private_len = 0;
	int present[5] = { 0 }, i, r = -1;
	const wchar_t *names[] = { L"pub", NULL, L"type", L"comment",
	    L"provider" };
	struct sshkey *key = NULL, *private_key = NULL;
	struct sshbuf *private_buf = NULL;
	char *private_blob = NULL, *provider = NULL;
	DWORD type;

	*keyp = NULL;
	*providerp = NULL;
	for (i = 0; i < 5; i++) {
		if (read_optional_reg_value(sub, names[i], &present[i],
		    &kind[i], &data[i], &len[i]) != 0)
			goto out;
		if ((i != 4 && !present[i]) ||
		    (present[i] && kind[i] != (i == 2 ? REG_DWORD : REG_BINARY)))
			goto out;
	}
	if (len[2] != sizeof(type) || len[0] == 0 || len[1] == 0 ||
	    memchr(data[3], '\0', len[3]) != NULL ||
	    sshkey_from_blob(data[0], len[0], &key) != 0)
		goto out;
	memcpy(&type, data[2], sizeof(type));
	if (type != (DWORD)key->type)
		goto out;
	if (len[1] == len[0] && memcmp(data[1], data[0], len[0]) == 0) {
		/* Old token entries use the comment as provider association. */
		i = present[4] ? 4 : 3;
		if (len[i] == 0 || memchr(data[i], '\0', len[i]) != NULL)
			goto out;
		provider = xmalloc((size_t)len[i] + 1);
		memcpy(provider, data[i], len[i]);
		provider[len[i]] = '\0';
		if (!pkcs11_provider_equal(data[i], len[i], provider))
			goto out;
	} else {
		if (present[4] || convert_blob(con, (char *)data[1], len[1],
		    &private_blob, &private_len, FALSE) != 0 ||
		    (private_buf = sshbuf_from(private_blob, private_len)) == NULL ||
		    sshkey_private_deserialize(private_buf, &private_key) != 0 ||
		    sshbuf_len(private_buf) != 0 || !sshkey_equal(key, private_key))
			goto out;
	}
	*keyp = key;
	key = NULL;
	*providerp = provider;
	provider = NULL;
	r = 0;
 out:
	for (i = 0; i < 5; i++)
		free(data[i]);
	if (private_blob != NULL) {
		SecureZeroMemory(private_blob, private_len);
		free(private_blob);
	}
	sshbuf_free(private_buf);
	sshkey_free(private_key);
	sshkey_free(key);
	free(provider);
	return r;
}

#pragma warning(pop)
