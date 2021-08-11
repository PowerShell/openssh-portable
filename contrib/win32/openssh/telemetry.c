// telemetry.c

#include "telemetry.h"
#include "telemetryInternal.h"

// {a20ded29-4533-5a0a-2a6d-42a888fb4015}
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider1,
    "Microsoft.Win32-OpenSSH.Encryption.Cipher",
    (0xa20ded29, 0x4533, 0x5a0a, 0x2a, 0x6d, 0x42, 0xa8, 0x88, 0xfb, 0x40, 0x15),
    TraceLoggingOptionMicrosoftTelemetry());

// send_telemetry("TEST cipher would go here")
void send_telemetry(const char* cipherField, const char* directionField)
{
    // Register the provider
    TraceLoggingRegister(g_hProvider1);
    // Log an event
    TraceLoggingWrite(
        g_hProvider1,
        "OpenSSHCipher", // Telemetry event names must start with a letter and may only contain [a-z], [A-Z], [0-9], and underscore.
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage), // Change PDT_ProductAndServiceUsage to a privacy category that fits your need
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES),
        TraceLoggingString(cipherField, "Cipher"),
        TraceLoggingString(directionField, "Direction") // Telemetry field names must start with a letter and may only contain [a-z], [A-Z], [0-9], and underscore.
    );
    //// Stop TraceLogging and unregister the provider
    TraceLoggingUnregister(g_hProvider1);
}
