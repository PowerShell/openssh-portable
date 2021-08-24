// telemetry.c

#include "telemetry.h"
#include "telemetryInternal.h"

// {a20ded29-4533-5a0a-2a6d-42a888fb4015}
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider1,
    "Microsoft.Win32-OpenSSH.Encryption.Cipher",
    (0xa20ded29, 0x4533, 0x5a0a, 0x2a, 0x6d, 0x42, 0xa8, 0x88, 0xfb, 0x40, 0x15),
    TraceLoggingOptionMicrosoftTelemetry());

void send_telemetry(const char* cipherField, const char* directionField)
{
    // Register the provider
    TraceLoggingRegister(g_hProvider1);
    // Log an event
    TraceLoggingWrite(
        g_hProvider1,
        "OpenSSHCipher", 
        TelemetryPrivacyDataTag(PDT_ProductAndServiceUsage), 
        TraceLoggingKeyword(MICROSOFT_KEYWORD_MEASURES), // MICROSOFT_KEYWORD_TELEMETRY if just logging, MICROSOFT_KEYWORD_MEASURES for sending
        TraceLoggingString(cipherField, "Cipher"),
        TraceLoggingString(directionField, "Direction") 
    );
    // Stop TraceLogging and unregister the provider
    TraceLoggingUnregister(g_hProvider1);
}
