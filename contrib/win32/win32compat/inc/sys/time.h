#pragma once
#include <sys\utime.h>

#define utimbuf _utimbuf
#define utimes w32_utimes

#define timeval w32_timeval
struct timeval
{
	long long	tv_sec;
	long        tv_usec;
};

int usleep(unsigned int);
int gettimeofday(struct timeval *, void *);
int nanosleep(const struct timespec *, struct timespec *);
int w32_utimes(const char *, struct timeval *);