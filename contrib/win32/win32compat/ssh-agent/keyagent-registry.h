/*
 * Registry and DPAPI helpers of the Windows ssh-agent key store.
 * Split out of keyagent-request.c.
 */

#pragma once

#include <Windows.h>

#include "sshbuf.h"

struct agent_connection;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME_LENGTH 16383
#define MAX_VALUE_DATA_LENGTH 2048

/* Registry keys are only accessible to SYSTEM and administrators. */
#define REG_KEY_SDDL L"D:P(A;; GA;;; SY)(A;; GA;;; BA)"

int get_user_root(struct agent_connection *, HKEY *);
int convert_blob(struct agent_connection *, const char *, DWORD, char **,
    DWORD *, int);
int remove_matching_subkeys_from_registry(HKEY, wchar_t const *,
    wchar_t const *, char const *);
int is_reg_sub_key_exists(HKEY, wchar_t const *, char const *);
int read_optional_reg_value(HKEY, const wchar_t *, int *, DWORD *,
    u_char **, DWORD *);
int restore_optional_reg_value(HKEY, const wchar_t *, int, DWORD,
    const u_char *, DWORD);
