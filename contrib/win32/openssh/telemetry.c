/* 
this file defines functions to collect Microsoft Telemetry,
which will only be sent for Windows In-Box releases. 
GitHub releases will not send any Telemetry. 
*/

#include <stdio.h>
#include <Objbase.h>

#include "telemetry.h"
#include "telemetryInternal.h"

// {0d986661-0dd7-561a-b15b-fcc1cd46d2bb}
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider1,
    "Microsoft.Windows.Win32OpenSSH",
    (0x0d986661, 0x0dd7, 0x561a, 0xb1, 0x5b, 0xfc, 0xc1, 0xcd, 0x46, 0xd2, 0xbb),
    TraceLoggingOptionMicrosoftTelemetry());

void send_auth_telemetry(const int status, const char* auth_type)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Auth",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingInt16(status, "Success"),
        TraceLoggingString(auth_type, "Auth Type")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_encryption_telemetry(const char* direction, const char* cipher, const char* kex,
    const char* mac, const char* comp, const char* host_key, const char** cproposal, const char** sproposal)
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
        TraceLoggingString(host_key, "host_key"),
        TraceLoggingString(cproposal[0], "client proposed kex"),
        TraceLoggingString(cproposal[1], "client proposed host keys"),
        TraceLoggingString(cproposal[2], "client proposed ciphers ctos"),
        TraceLoggingString(cproposal[3], "client proposed ciphers stoc"),
        TraceLoggingString(cproposal[4], "client proposed MACs ctos"),
        TraceLoggingString(cproposal[5], "client proposed MACs stoc"),
        TraceLoggingString(cproposal[6], "client proposed compression ctos"),
        TraceLoggingString(cproposal[7], "client proposed compression stoc"),
        TraceLoggingString(sproposal[0], "server proposed kex"),
        TraceLoggingString(sproposal[1], "server proposed host keys"),
        TraceLoggingString(sproposal[2], "server proposed ciphers ctos"),
        TraceLoggingString(sproposal[3], "server proposed ciphers stoc"),
        TraceLoggingString(sproposal[4], "server proposed MACs ctos"),
        TraceLoggingString(sproposal[5], "server proposed MACs stoc"),
        TraceLoggingString(sproposal[6], "server proposed compression ctos"),
        TraceLoggingString(sproposal[7], "server proposed compression stoc")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_key_telemetry(const char* key)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Key",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(key, "Status")
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
        TraceLoggingInt16(shell_type, "Type")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_sign_telemetry(const char* sign_status)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Signing",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(sign_status, "Status")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_ssh_telemetry(const char* conn)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Connection",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(conn, "Status")
    );
    TraceLoggingUnregister(g_hProvider1);
}

void send_sshd_telemetry(const int num_auth_methods, const char** auth_methods,
    const unsigned int num_ports, const int ports[])
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
        auth_buffer = (char*)malloc(buffer_size * sizeof(char));
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
        TraceLoggingInt32Array(ports, num_ports, "Port"),
        TraceLoggingString(auth_buffer, "Auth Methods")
    );
    TraceLoggingUnregister(g_hProvider1);
    free(auth_buffer);
}

void send_startup_telemetry(const char* ssh_version, const char* peer_version, 
    const char* remote_protocol_supported)
{
    TraceLoggingRegister(g_hProvider1);
    TraceLoggingWrite(
        g_hProvider1,
        "Startup",
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage),
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(ssh_version, " our version"),
        TraceLoggingString(remote_protocol_supported, "remote protocol error"),
        TraceLoggingString(peer_version, "peer version")
    );
    TraceLoggingUnregister(g_hProvider1);
}

