/*
 * Author: Steffen Heil <steffen.heil@secforge.de>
 *
 * Tests for the Win32 getifaddrs()/freeifaddrs() implementation
 * (contrib/win32/win32compat/getifaddrs.c).
 */

#include "includes.h"
#include <sys/socket.h>
#include <ifaddrs.h>

#include "../test_helper/test_helper.h"
#include "tests.h"

void
getifaddrs_tests()
{
	struct ifaddrs *ifap = NULL, *ifa;
	int r, count = 0, loopback_up = 0;

	TEST_START("getifaddrs returns a populated list");
	r = getifaddrs(&ifap);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(ifap, NULL);
	TEST_DONE();

	TEST_START("getifaddrs entries are well-formed");
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		count++;
		ASSERT_PTR_NE(ifa->ifa_addr, NULL);
		ASSERT_PTR_NE(ifa->ifa_name, NULL);
		/* loopback must be present and marked up (sanity baseline) */
		if (ifa->ifa_addr->sa_family == AF_INET &&
		    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr ==
		    htonl(INADDR_LOOPBACK) &&
		    (ifa->ifa_flags & IFF_UP) != 0)
			loopback_up = 1;
	}
	ASSERT_INT_NE(count, 0);
	TEST_DONE();

	TEST_START("loopback 127.0.0.1 is present and flagged IFF_UP");
	ASSERT_INT_EQ(loopback_up, 1);
	TEST_DONE();

	freeifaddrs(ifap);

	TEST_START("freeifaddrs(NULL) is a no-op");
	freeifaddrs(NULL);
	TEST_DONE();
}
