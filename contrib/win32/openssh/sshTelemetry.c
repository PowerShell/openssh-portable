/*
* Author: Tess Gauthier <tessgauthier@microsoft.com>
*
* Copyright(c) 2021 Microsoft Corp.
* All rights reserved
*
* Misc Unix POSIX routine implementations for Windows
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met :
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and / or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/ 

/*
this file defines functions to collect Microsoft Telemetry,
which will only be sent for Windows In-Box releases. 
GitHub releases will not send any Telemetry. 
*/

#include <string.h>
#include <stdio.h>
#include <Objbase.h>

#include "sshTelemetry.h"
#include "sshTelemetryInternal.h"

// {0d986661-0dd7-561a-b15b-fcc1cd46d2bb}
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider1,
    "Microsoft.Windows.Win32OpenSSH",
    (0x0d986661, 0x0dd7, 0x561a, 0xb1, 0x5b, 0xfc, 0xc1, 0xcd, 0x46, 0xd2, 0xbb),
    TraceLoggingOptionMicrosoftTelemetry());

void send_auth_telemetry(const int status, const char* auth_type)
{
    /* 
    registering only needs to be done once per process but
    since these functions are used by multiple processes
    and we need to unregister so the ETW process knows
    not to do any callbacks, registering and unregistering 
    is done after each tracelogging call for safety 
    */
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Auth",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingInt16(status, "success"),
        TraceLoggingString(auth_type, "authType")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_encryption_telemetry(const char* direction, 
    const char* cipher, const char* kex, const char* mac, 
    const char* comp, const char* host_key, 
    const char** cproposal, const char** sproposal)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Encryption",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(direction, "direction"),
        TraceLoggingString(cipher, "cipher"),
        TraceLoggingString(kex, "kex"),
        TraceLoggingString(mac, "mac"),
        TraceLoggingString(comp, "compression"),
        TraceLoggingString(host_key, "hostKey"),
        TraceLoggingString(cproposal[0], "clientProposedKex"),
        TraceLoggingString(cproposal[1], "clientProposedHostKeys"),
        TraceLoggingString(cproposal[2], "clientProposedCiphersCtos"),
        TraceLoggingString(cproposal[3], "clientProposedCiphersStoc"),
        TraceLoggingString(cproposal[4], "clientProposedMACsCtos"),
        TraceLoggingString(cproposal[5], "clientProposedMACsStoc"),
        TraceLoggingString(cproposal[6], "clientProposedCompressionCtos"),
        TraceLoggingString(cproposal[7], "clientProposedCompressionStoc"),
        TraceLoggingString(sproposal[0], "serverProposedKex"),
        TraceLoggingString(sproposal[1], "serverProposedHostKeys"),
        TraceLoggingString(sproposal[2], "serverProposedCiphersCtos"),
        TraceLoggingString(sproposal[3], "serverProposedCiphersStoc"),
        TraceLoggingString(sproposal[4], "serverProposedMACsCtos"),
        TraceLoggingString(sproposal[5], "serverProposedMACsCtoc"),
        TraceLoggingString(sproposal[6], "serverProposedCompressionCtos"),
        TraceLoggingString(sproposal[7], "serverProposedCompressionStoc")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_pubkey_telemetry(const char* pubKeyStatus)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "PublicKey",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(pubKeyStatus, "status")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_shell_telemetry(const int pty, const int shell_type)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Shell",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingInt16(pty, "PTY"),
        TraceLoggingInt16(shell_type, "type")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_pubkey_sign_telemetry(const char* pubKeySignStatus)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "PubkeySigning",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(pubKeySignStatus, "status")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_ssh_connection_telemetry(const char* conn, const char* port)
{
    int isCustomPort = 0;
    if (strcmp(port, "22") != 0) {
        isCustomPort = 1;
    }
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Connection",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(conn, "status"),
        TraceLoggingBool(isCustomPort, "isCustomSSHServerPort")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_sshd_config_telemetry(const int num_auth_methods, 
    const char** auth_methods)
{
    char* auth_buffer = NULL;
    if (num_auth_methods == 0) {
        auth_buffer = (char*)malloc(5 * sizeof(char));
        strcpy_s(auth_buffer, 5, "none");
    }
    else {
        // concatenate all the auth methods into a 
        // single string to pass to tracelogging
        size_t buffer_size = (size_t)num_auth_methods;
        for (int i = 0; i < num_auth_methods; i++) {
            buffer_size += strlen(auth_methods[i]);
        }
        auth_buffer = (char*)malloc((buffer_size + 1) * sizeof(char));
        auth_buffer[0] = '\0';
        for (int i = 0; i < num_auth_methods; i++) {
            strcat_s(auth_buffer, buffer_size, auth_methods[i]);
            if (i < num_auth_methods - 1) {
                strcat_s(auth_buffer, buffer_size, ",");
            }
        }
    }
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "SSHD",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(auth_buffer, "Auth Methods")
    );
    TraceLoggingUnregister(g_hProvider1);
    free(auth_buffer);
}

void send_ssh_version_telemetry(const char* ssh_version, const char* peer_version,
    const char* remote_protocol_supported)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Startup",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(ssh_version, "our version"),
        TraceLoggingString(remote_protocol_supported, "remote protocol error"),
        TraceLoggingString(peer_version, "peer version")
    );
    TraceLoggingUnregister(g_hProvider1);
}

