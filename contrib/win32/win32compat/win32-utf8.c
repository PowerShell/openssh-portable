/* 
 * Temporary Windows versions of functions implemented in utf8.c
 */
 #include <stdio.h>
#include <stdarg.h>

int
vfmprintf(FILE *f, const char *fmt, va_list list) 
{
	return vfprintf(f, fmt, list);
}

int
mprintf(const char *fmt, ...) 
{
	va_list valist;
	va_start(valist, fmt);
	vfmprintf(stdout, fmt, valist);
	va_end(valist);
	return 0;
}

int
fmprintf(FILE *f, const char *fmt, ...) 
{
	va_list valist;
	va_start(valist, fmt);
	vfmprintf(f, fmt, valist);
	va_end(valist);
	return 0;
}

int
snmprintf(char *buf, size_t len, int *written, const char *fmt, ...) 
{
	int num;
	va_list valist;
	va_start(valist, fmt);
	num = vsnprintf(buf, len, fmt, valist);
	va_end(valist);
	*written = num;
	return 0;
}

void
msetlocale(void) 
{
	return;
}

