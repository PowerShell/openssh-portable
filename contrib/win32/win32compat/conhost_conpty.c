/*
* Author: Balu G <bagajjal@microsoft.com>
*
* This file contains the conpty related functions.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "includes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

#include "conhost_conpty.h"

const unsigned int PTY_SIGNAL_RESIZE_WINDOW = 8u;

// Return Value: 0 for success, -1 for failure
int
CreateConPty(const char *cmdline,
	const unsigned short width,
	const unsigned short height,
	HANDLE const hInput,
	HANDLE const hOutput,	
	HANDLE* const conhost_pty_sighandle,
	PROCESS_INFORMATION* const piPty)
{
	HANDLE signal_pipe_conhost_side;
	SECURITY_ATTRIBUTES sa;
	char system32_path[PATH_MAX] = { 0, };

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);	
	sa.lpSecurityDescriptor = NULL;	
	sa.bInheritHandle = TRUE;
	
	CreatePipe(&signal_pipe_conhost_side, conhost_pty_sighandle, &sa, 0);
	SetHandleInformation(*conhost_pty_sighandle, HANDLE_FLAG_INHERIT, 0);

	char conhostCmdline[8191] = { 0, }; // msdn	
	char *cmd_fmt = "%s\\conhost.exe --headless --width %d --height %d --signal 0x%x -- %s";
	
	if (!GetSystemDirectoryA(system32_path, PATH_MAX))
		fatal("unable to retrieve system32 path");
	
	snprintf(conhostCmdline,
		_countof(conhostCmdline),
		cmd_fmt,
		system32_path,
		width,
		height,
		signal_pipe_conhost_side,
		cmdline);
	
	STARTUPINFO si;
	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFOW);
	si.hStdInput = hInput;
	si.hStdOutput = hOutput;	
	si.hStdError = hOutput;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESIZE | STARTF_USECOUNTCHARS;

	debug3("conhostcmdline:%s", conhostCmdline);
	
	if (0 == CreateProcess(NULL, conhostCmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, piPty)) {
		debug("Failed to create the conhost pty, error:%d", GetLastError());
		
		return -1;
	}

	return 0;
}

// Return 1 if the resize succeeded, else 0.
int
SignalResizeWindow(const HANDLE conhost_pty_sighandle, const unsigned short width, const unsigned short height)
{
	unsigned short signalPacket[3];
	signalPacket[0] = PTY_SIGNAL_RESIZE_WINDOW;
	signalPacket[1] = width;
	signalPacket[2] = height;
	// TODO - xpixel, ypixel
	if (!WriteFile(conhost_pty_sighandle, signalPacket, sizeof(signalPacket), NULL, NULL)) {
		debug("Failed to write resize window event to the conhost pty, error:%d", GetLastError());		
		return -1;
	}

	debug3("Successfully sent the resize window event to conhost pty, width:%d height:%d", width, height);

	return 0;
}

int
is_conpty_supported()
{
	// TODO - 
	// As of today, conpty doesn't have a way to distinguish between RS5 and above (VS) downlevel.
	// The below logic should be enabled once conpty changes are in place.
	return 1; 

//	wchar_t system32_path[PATH_MAX] = { 0, };
//	wchar_t kernelbase_dll_path[PATH_MAX] = { 0, };
//	HMODULE hm_kernelbase = NULL;
//
//	int retVal = 0;
//	
//	if (!GetSystemDirectoryW(system32_path, PATH_MAX))
//		goto done;
//	
//	wcscat_s(kernelbase_dll_path, PATH_MAX, system32_path);
//	wcscat_s(kernelbase_dll_path, PATH_MAX, L"\\KernelBase.dll");
//
//	if ((hm_kernelbase = LoadLibraryW(kernelbase_dll_path)) == NULL) {
//		error("failed to load kernerlbase dll:%s", kernelbase_dll_path);
//		goto done;
//	}
//
//	if (GetProcAddress(hm_kernelbase, "CreatePseudoConsole") == NULL) {
//		debug3("couldn't find CreatePseudoConsole() in kernerlbase dll");
//		goto done;
//	}
//
//	retVal = 1;
//
//done:
//	if (!retVal)
//		debug3("This windows OS doesn't support conpty");
//
//	return retVal;
}
