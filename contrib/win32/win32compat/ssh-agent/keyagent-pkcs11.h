/*
 * PKCS#11 provider and identity persistence of the Windows ssh-agent.
 * Split out of keyagent-request.c.
 */

#pragma once

#include <Windows.h>

#include "sshkey.h"

#ifdef ENABLE_PKCS11
void free_pkcs11_sign_provider(char **, char **, DWORD, char **, DWORD,
    struct sshkey ***, int);
int load_pkcs11_identities(HKEY, const char *, struct sshkey **, int);
#endif /* ENABLE_PKCS11 */
