#pragma once

#include <windows.h> // Defines macros used by TraceLoggingProvider.h
#include "TraceLoggingProvider.h"  // The native TraceLogging API
#include "MicrosoftTelemetry.h"

// Forward-declare the g_hMyComponentProvider variable that you will use for tracing in this component
TRACELOGGING_DECLARE_PROVIDER(g_hProvider1);
