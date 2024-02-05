#pragma once

#include <windows.h> // Defines macros used by TraceLoggingProvider.h
#include "TraceLoggingProvider.h"  // The native TraceLogging API
#include "MicrosoftTelemetry.h"

// Forward-declare the g_hProvider1 variable that you will use for tracing
TRACELOGGING_DECLARE_PROVIDER(g_hProvider1);