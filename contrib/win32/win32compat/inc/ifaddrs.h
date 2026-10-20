/*
 * Author: Steffen Heil <steffen.heil@secforge.de>
 *
 * POSIX getifaddrs(3) interface for Windows.
 *
 * Declares struct ifaddrs and the getifaddrs()/freeifaddrs() functions that
 * are implemented in win32compat\getifaddrs.c on top of the Win32
 * GetAdaptersAddresses() API. This allows the portable OpenSSH code that
 * enumerates local interface addresses (e.g. the "Match localnetwork"
 * criterion and "BindInterface") to build and work on Windows.
 *
 * Copyright (c) 2026 Steffen Heil
 * All rights reserved
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

#pragma once

#include "sys\socket.h"		/* struct sockaddr */

/*
 * Interface flags. Windows has no <net/if.h> equivalent, so define the
 * subset that the portable code inspects (only IFF_UP is currently used).
 */
#ifndef IFF_UP
#define IFF_UP		0x1	/* interface is up */
#endif
#ifndef IFF_BROADCAST
#define IFF_BROADCAST	0x2	/* broadcast address valid */
#endif
#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK	0x8	/* is a loopback net */
#endif
#ifndef IFF_POINTOPOINT
#define IFF_POINTOPOINT	0x10	/* interface is point-to-point link */
#endif
#ifndef IFF_RUNNING
#define IFF_RUNNING	0x40	/* resources allocated */
#endif
#ifndef IFF_MULTICAST
#define IFF_MULTICAST	0x1000	/* supports multicast */
#endif

struct ifaddrs {
	struct ifaddrs  *ifa_next;	/* next item in the list */
	char            *ifa_name;	/* name of the interface */
	unsigned int     ifa_flags;	/* flags from SIOCGIFFLAGS (IFF_*) */
	struct sockaddr *ifa_addr;	/* interface address */
	struct sockaddr *ifa_netmask;	/* interface netmask */
	union {
		struct sockaddr *ifu_broadaddr;	/* broadcast address */
		struct sockaddr *ifu_dstaddr;	/* point-to-point dest addr */
	} ifa_ifu;
	void            *ifa_data;	/* address-family specific data */
};

#define ifa_broadaddr	ifa_ifu.ifu_broadaddr
#define ifa_dstaddr	ifa_ifu.ifu_dstaddr

int getifaddrs(struct ifaddrs **ifap);
void freeifaddrs(struct ifaddrs *ifa);
