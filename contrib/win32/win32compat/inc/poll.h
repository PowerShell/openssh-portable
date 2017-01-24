#pragma once

#include "sys\types.h"

/* created to #def out decarations in open-bsd.h (that are defined in winsock2.h) */

struct w32_pollfd {

	int  fd;
	short   events;
	short   revents;

};

#define pollfd w32_pollfd

int poll(struct pollfd *, nfds_t, int);