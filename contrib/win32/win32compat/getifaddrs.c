/*
 * Author: Steffen Heil <steffen.heil@secforge.de>
 *
 * POSIX getifaddrs(3) emulation for Windows.
 *
 * Implements getifaddrs()/freeifaddrs() on top of the Win32
 * GetAdaptersAddresses() API so that the portable OpenSSH code that
 * enumerates local interface addresses (e.g. the "Match localnetwork"
 * criterion and "BindInterface") builds and works on Windows.
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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "inc\ifaddrs.h"

/* Iphlpapi.lib (GetAdaptersAddresses) is linked via the consuming project. */

/* Recommended initial allocation size from the GetAdaptersAddresses docs. */
#define WORKING_BUFFER_SIZE 15000
/* Bound the resize retries should the adapter set keep growing. */
#define MAX_TRIES 3

/* Duplicate a sockaddr of the given length. */
static struct sockaddr *
sockaddr_dup(const struct sockaddr *sa, size_t salen)
{
	struct sockaddr *ret;

	if (sa == NULL || salen == 0)
		return NULL;
	if ((ret = malloc(salen)) == NULL)
		return NULL;
	memcpy(ret, sa, salen);
	return ret;
}

/* Build a netmask sockaddr for the given family from a CIDR prefix length. */
static struct sockaddr *
prefix_to_netmask(int family, unsigned int prefixlen)
{
	if (family == AF_INET) {
		struct sockaddr_in *sin;

		if ((sin = calloc(1, sizeof(*sin))) == NULL)
			return NULL;
		sin->sin_family = AF_INET;
		if (prefixlen > 32)
			prefixlen = 32;
		if (prefixlen != 0)
			sin->sin_addr.s_addr =
			    htonl(0xffffffffu << (32 - prefixlen));
		return (struct sockaddr *)sin;
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sin6;
		unsigned int i;

		if ((sin6 = calloc(1, sizeof(*sin6))) == NULL)
			return NULL;
		sin6->sin6_family = AF_INET6;
		if (prefixlen > 128)
			prefixlen = 128;
		for (i = 0; i < prefixlen; i++)
			sin6->sin6_addr.s6_addr[i / 8] |=
			    (unsigned char)(0x80 >> (i % 8));
		return (struct sockaddr *)sin6;
	}
	return NULL;
}

void
freeifaddrs(struct ifaddrs *ifa)
{
	struct ifaddrs *next;

	while (ifa != NULL) {
		next = ifa->ifa_next;
		free(ifa->ifa_name);
		free(ifa->ifa_addr);
		free(ifa->ifa_netmask);
		free(ifa);
		ifa = next;
	}
}

int
getifaddrs(struct ifaddrs **ifap)
{
	IP_ADAPTER_ADDRESSES *adapters = NULL, *aa;
	IP_ADAPTER_UNICAST_ADDRESS *ua;
	struct ifaddrs *head = NULL, *cur, **nextp = &head;
	ULONG size = WORKING_BUFFER_SIZE, ret = 0;
	int tries = 0;
	const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
	    GAA_FLAG_SKIP_DNS_SERVER;

	if (ifap == NULL) {
		errno = EINVAL;
		return -1;
	}
	*ifap = NULL;

	/* Retry while the adapter information does not fit the buffer. */
	do {
		free(adapters);
		if ((adapters = malloc(size)) == NULL) {
			errno = ENOMEM;
			return -1;
		}
		ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL,
		    adapters, &size);
	} while (ret == ERROR_BUFFER_OVERFLOW && ++tries < MAX_TRIES);

	if (ret == ERROR_NO_DATA) {
		/* No usable addresses present; an empty list is not an error. */
		free(adapters);
		return 0;
	}
	if (ret != NO_ERROR) {
		free(adapters);
		errno = (ret == ERROR_NOT_ENOUGH_MEMORY) ? ENOMEM : ENXIO;
		return -1;
	}

	for (aa = adapters; aa != NULL; aa = aa->Next) {
		char *name = NULL;
		int namelen = 0;

		/*
		 * ifa_name is the adapter friendly name (UTF-16 -> UTF-8),
		 * e.g. "Ethernet" or "Wi-Fi" -- this is what ssh's
		 * BindInterface matches against on Windows. Fall back to the
		 * adapter GUID name if the friendly name is unavailable.
		 */
		if (aa->FriendlyName != NULL &&
		    (namelen = WideCharToMultiByte(CP_UTF8, 0, aa->FriendlyName,
		    -1, NULL, 0, NULL, NULL)) > 0) {
			if ((name = malloc(namelen)) != NULL &&
			    WideCharToMultiByte(CP_UTF8, 0, aa->FriendlyName, -1,
			    name, namelen, NULL, NULL) <= 0) {
				free(name);
				name = NULL;
			}
		}
		/* Fall back to the (ANSI) adapter GUID name. */
		if (name == NULL && aa->AdapterName != NULL)
			name = _strdup(aa->AdapterName);

		for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
			SOCKET_ADDRESS *sa = &ua->Address;
			int family;

			if (sa->lpSockaddr == NULL)
				continue;
			family = sa->lpSockaddr->sa_family;
			if (family != AF_INET && family != AF_INET6)
				continue;

			if ((cur = calloc(1, sizeof(*cur))) == NULL) {
				free(name);
				goto nomem;
			}
			cur->ifa_addr = sockaddr_dup(sa->lpSockaddr,
			    sa->iSockaddrLength);
			if (cur->ifa_addr == NULL) {
				free(cur);
				free(name);
				goto nomem;
			}
			/* Best-effort; consumers only require ifa_addr. */
			cur->ifa_netmask = prefix_to_netmask(family,
			    ua->OnLinkPrefixLength);
			if (name != NULL &&
			    (cur->ifa_name = _strdup(name)) == NULL) {
				free(cur->ifa_addr);
				free(cur->ifa_netmask);
				free(cur);
				free(name);
				goto nomem;
			}

			if (aa->OperStatus == IfOperStatusUp)
				cur->ifa_flags |= IFF_UP | IFF_RUNNING;
			if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
				cur->ifa_flags |= IFF_LOOPBACK;
			if ((aa->Flags & IP_ADAPTER_NO_MULTICAST) == 0)
				cur->ifa_flags |= IFF_MULTICAST;

			*nextp = cur;
			nextp = &cur->ifa_next;
		}
		free(name);
	}

	free(adapters);
	*ifap = head;
	return 0;

 nomem:
	freeifaddrs(head);
	free(adapters);
	errno = ENOMEM;
	return -1;
}
