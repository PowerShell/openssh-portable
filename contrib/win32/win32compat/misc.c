/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Copyright(c) 2016 Microsoft Corp.
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

#include <Windows.h>
#include <stdio.h>
#include "inc\defs.h"
#include "inc\sys\statvfs.h"
#include "inc\sys\time.h"
#include <time.h>

int usleep(unsigned int useconds)
{
	Sleep(useconds / 1000);
	return 1;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
        HANDLE timer;
        LARGE_INTEGER li;

        if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec > 999999999) {
                errno = EINVAL;
                return -1;
        }

        if ((timer = CreateWaitableTimerW(NULL, TRUE, NULL)) == NULL) {
                errno = EFAULT;
                return -1;
        }

        li.QuadPart = -req->tv_nsec;
        if (!SetWaitableTimer(timer, &li, 0, NULL, NULL, FALSE)) {
                CloseHandle(timer);
                errno = EFAULT;
                return -1;
        }
        
        /* TODO - use wait_for_any_event, since we want to wake up on interrupts*/
        switch (WaitForSingleObject(timer, INFINITE)) {
        case WAIT_OBJECT_0:
                CloseHandle(timer);
                return 0;
        default:
                errno = EFAULT;
                return -1;
        }
}

/* Difference in us between UNIX Epoch and Win32 Epoch */
#define EPOCH_DELTA_US  11644473600000000ULL

/* This routine is contributed by  * Author: NoMachine <developers@nomachine.com>
* Copyright (c) 2009, 2010 NoMachine
* All rights reserved
*/
int
gettimeofday(struct timeval *tv, void *tz)
{
        union
        {
                FILETIME ft;
                unsigned long long ns;
        } timehelper;
        unsigned long long us;

        /* Fetch time since Jan 1, 1601 in 100ns increments */
        GetSystemTimeAsFileTime(&timehelper.ft);

        /* Convert to microseconds from 100 ns units */
        us = timehelper.ns / 10;

        /* Remove the epoch difference */
        us -= EPOCH_DELTA_US;

        /* Stuff result into the timeval */
        tv->tv_sec = (long)(us / 1000000ULL);
        tv->tv_usec = (long)(us % 1000000ULL);

        return 0;
}

void
explicit_bzero(void *b, size_t len) {
	SecureZeroMemory(b, len);
}

int statvfs(const char *path, struct statvfs *buf) {
	DWORD sectorsPerCluster;
	DWORD bytesPerSector;
	DWORD freeClusters;
	DWORD totalClusters;

	if (GetDiskFreeSpace(path, &sectorsPerCluster, &bytesPerSector,
		&freeClusters, &totalClusters) == TRUE)
	{
		debug3("path              : [%s]", path);
		debug3("sectorsPerCluster : [%lu]", sectorsPerCluster);
		debug3("bytesPerSector    : [%lu]", bytesPerSector);
		debug3("bytesPerCluster   : [%lu]", sectorsPerCluster * bytesPerSector);
		debug3("freeClusters      : [%lu]", freeClusters);
		debug3("totalClusters     : [%lu]", totalClusters);

		buf->f_bsize = sectorsPerCluster * bytesPerSector;
		buf->f_frsize = sectorsPerCluster * bytesPerSector;
		buf->f_blocks = totalClusters;
		buf->f_bfree = freeClusters;
		buf->f_bavail = freeClusters;
		buf->f_files = -1;
		buf->f_ffree = -1;
		buf->f_favail = -1;
		buf->f_fsid = 0;
		buf->f_flag = 0;
		buf->f_namemax = MAX_PATH - 1;

		return 0;
	}
	else
	{
		debug3("ERROR: Cannot get free space for [%s]. Error code is : %d.\n",
			path, GetLastError());

		return -1;
	}
}

int fstatvfs(int fd, struct statvfs *buf) {
	errno = ENOSYS;
	return -1;
}

#include "inc\dlfcn.h"
HMODULE dlopen(const char *filename, int flags) {
	return LoadLibraryA(filename);
}

int dlclose(HMODULE handle) {
	FreeLibrary(handle);
	return 0;
}

FARPROC dlsym(HMODULE handle, const char *symbol) {
	return GetProcAddress(handle, symbol);
}


/*fopen on Windows to mimic https://linux.die.net/man/3/fopen
* only r, w, a are supported for now
*/
FILE*
w32_fopen_utf8(const char *path, const char *mode) {
	wchar_t wpath[MAX_PATH], wmode[5];
	FILE* f;
	char utf8_bom[] = { 0xEF,0xBB,0xBF };
	char first3_bytes[3];

	if (mode[1] != '\0') {
		errno = ENOTSUP;
		return NULL;
	}

	if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH) == 0 ||
		MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 5) == 0) {
		errno = EFAULT;
		debug("WideCharToMultiByte failed for %c - ERROR:%d", path, GetLastError());
		return NULL;
	}

	f = _wfopen(wpath, wmode);

	if (f) {
		/* BOM adjustments for file streams*/
		if (mode[0] == 'w' && fseek(f, 0, SEEK_SET) != EBADF) {
			/* write UTF-8 BOM - should we ?*/
			/*if (fwrite(utf8_bom, sizeof(utf8_bom), 1, f) != 1) {
				fclose(f);
				return NULL;
			}*/

		}
		else if (mode[0] == 'r' && fseek(f, 0, SEEK_SET) != EBADF) {
			/* read out UTF-8 BOM if present*/
			if (fread(first3_bytes, 3, 1, f) != 1 ||
				memcmp(first3_bytes, utf8_bom, 3) != 0) {
				fseek(f, 0, SEEK_SET);
			}
		}
	}

	return f;
}


wchar_t*
utf8_to_utf16(const char *utf8) {
        int needed = 0;
        wchar_t* utf16 = NULL;
        if ((needed = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0)) == 0 ||
                (utf16 = malloc(needed * sizeof(wchar_t))) == NULL ||
                MultiByteToWideChar(CP_UTF8, 0, utf8, -1, utf16, needed) == 0)
                return NULL;
        return utf16;
}

char*
utf16_to_utf8(const wchar_t* utf16) {
        int needed = 0;
        char* utf8 = NULL;
        if ((needed = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, NULL, 0, NULL, NULL)) == 0 ||
                (utf8 = malloc(needed)) == NULL ||
                WideCharToMultiByte(CP_UTF8, 0, utf16, -1, utf8, needed, NULL, NULL) == 0)
                return NULL;
        return utf8;
}

static char* s_programdir = NULL;
char* w32_programdir() {
        if (s_programdir != NULL)
                return s_programdir;

        if ((s_programdir = utf16_to_utf8(_wpgmptr)) == NULL)
                return NULL;

        /* null terminate after directory path */
        {
                char* tail = s_programdir + strlen(s_programdir);
                while (tail > s_programdir && *tail != '\\' && *tail != '/')
                        tail--;

                if (tail > s_programdir)
                        *tail = '\0';
                else
                        *tail = '.'; /* current directory */
        }

        return s_programdir;

}

int 
daemon(int nochdir, int noclose)
{
        FreeConsole();
        return 0;
}

int w32_ioctl(int d, int request, ...) {
        va_list valist;
        va_start(valist, request);

        switch (request){
        case TIOCGWINSZ: {
                struct winsize* wsize = va_arg(valist, struct winsize*);
                CONSOLE_SCREEN_BUFFER_INFO c_info;
                if (wsize == NULL || !GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &c_info)) {
                        errno = EINVAL;
                        return -1;
                }
                wsize->ws_col = c_info.dwSize.X - 5;
                wsize->ws_row = c_info.dwSize.Y;
                wsize->ws_xpixel = 640;
                wsize->ws_ypixel = 480;
                return 0;
        }
        default:
                errno = ENOTSUP;
                return -1;
        }
}

HANDLE w32_fd_to_handle(int fd);
int 
spawn_child(char* cmd, int in, int out, int err, DWORD flags) {
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	BOOL b;
	wchar_t * cmd_utf16;

	debug("spawning %s", cmd);

	if ((cmd_utf16 = utf8_to_utf16(cmd)) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	memset(&si, 0, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	si.hStdInput = w32_fd_to_handle(in);
	si.hStdOutput = w32_fd_to_handle(out);
	si.hStdError = w32_fd_to_handle(err);
	si.dwFlags = STARTF_USESTDHANDLES;

	b = CreateProcessW(NULL, cmd_utf16, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi);

	if (b) {
		if (sw_add_child(pi.hProcess, pi.dwProcessId) == -1) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			pi.dwProcessId = -1;
		}
		CloseHandle(pi.hThread);
	}
	else {
		errno = GetLastError();
		pi.dwProcessId = -1;
	}

	free(cmd_utf16);
	return pi.dwProcessId;
}