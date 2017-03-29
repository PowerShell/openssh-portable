/* 
 * Windows versions of functions implemented in utf8.c
 */
#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

#include "console.h"

HANDLE get_console_handle(FILE *, DWORD * );

int
vfmprintf(FILE *stream, const char *fmt, va_list ap)
{
	DWORD saved_mode = 0, new_mode = 0;
	int ret;
	HANDLE hFile;
	hFile = get_console_handle(stream, &saved_mode);
	if(hFile != INVALID_HANDLE_VALUE &&
		((saved_mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
			new_mode = saved_mode & (~ENABLE_VIRTUAL_TERMINAL_PROCESSING);
			SetConsoleMode(hFile, new_mode);
	}
	
	ret = vfprintf(stream, fmt, ap);
	if (saved_mode != 0 && new_mode != saved_mode)
		SetConsoleMode(hFile, saved_mode);
	return ret;
}

int
mprintf(const char *fmt, ...)
{
	int ret = 0;
	va_list ap;
	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	return ret;
}

int
fmprintf(FILE *stream, const char *fmt, ...)
{
	int ret = 0;
	va_list ap;
	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	return ret;
}

int
snmprintf(char *buf, size_t len, int *written, const char *fmt, ...)
{
	int ret;
	va_list valist;
	va_start(valist, fmt);
	if ((ret = vsnprintf(buf, len, fmt, valist)) >= len)
		ret = len;
	va_end(valist);
	if (written != NULL && ret != -1)
		*written = ret;
	return ret;
}

void
msetlocale(void)
{
}

