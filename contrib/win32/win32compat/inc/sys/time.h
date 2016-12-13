#include <sys\utime.h>

#define utimbuf _utimbuf
#define utime _utime
int usleep(unsigned int);
int gettimeofday(struct timeval *tv, void *tz);
int nanosleep(const struct timespec *req, struct timespec *rem);
