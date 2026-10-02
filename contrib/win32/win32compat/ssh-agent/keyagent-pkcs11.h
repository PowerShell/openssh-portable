/*
 * PKCS#11 provider and identity persistence of the Windows ssh-agent.
 * Split out of keyagent-request.c.
 *
 * Without ENABLE_PKCS11 the functions below are no-ops, so callers do not
 * need any conditional compilation.
 */

#pragma once

#include <Windows.h>

#include "sshkey.h"

struct agent_connection;

#ifdef ENABLE_PKCS11

/* Key that was loaded from a PKCS#11 provider by the current request. */
struct sshkey *keyagent_pkcs11_lookup_key(const struct sshkey *);

/*
 * Load all persisted providers and make their identities available to
 * signing. Must be paired with keyagent_pkcs11_release(), also on failure.
 */
int keyagent_pkcs11_reload_providers(struct agent_connection *);
void keyagent_pkcs11_release(void);

/* Delete the persisted PKCS#11 certificate identity matching key/blob. */
LSTATUS keyagent_pkcs11_delete_cert_identity(HKEY, const struct sshkey *,
    const u_char *, size_t);

#else /* ENABLE_PKCS11 */

static __inline struct sshkey *
keyagent_pkcs11_lookup_key(const struct sshkey *key)
{
	return NULL;
}

static __inline int
keyagent_pkcs11_reload_providers(struct agent_connection *con)
{
	return 0;
}

static __inline void
keyagent_pkcs11_release(void)
{
}

static __inline LSTATUS
keyagent_pkcs11_delete_cert_identity(HKEY root, const struct sshkey *key,
    const u_char *blob, size_t blob_len)
{
	return ERROR_FILE_NOT_FOUND;
}

#endif /* ENABLE_PKCS11 */
