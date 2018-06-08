#include <windows.h>
#pragma once

int CreateConPty(const char *cmdline,
	const unsigned short width,
	const unsigned short height,
	HANDLE const hInput,
	HANDLE const hOutput,
	HANDLE* const hSignal,
	PROCESS_INFORMATION* const piPty);

int SignalResizeWindow(const HANDLE hSignal,
	const unsigned short width,
	const unsigned short height);

int is_conpty_supported();
