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
	int r;

	/*
	 * getifaddrs() may legitimately return an empty list (no configured
	 * addresses), so assert only the call result and per-entry invariants
	 * -- not the presence of any particular interface, which would be
	 * environment-dependent and flaky.
	 */
	TEST_START("getifaddrs succeeds");
	r = getifaddrs(&ifap);
	ASSERT_INT_EQ(r, 0);
	TEST_DONE();

	TEST_START("getifaddrs entries are well-formed");
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		ASSERT_PTR_NE(ifa->ifa_name, NULL);   /* contract: always set */
		ASSERT_PTR_NE(ifa->ifa_addr, NULL);
		ASSERT_INT_EQ(ifa->ifa_addr->sa_family == AF_INET ||
		    ifa->ifa_addr->sa_family == AF_INET6, 1);
	}
	TEST_DONE();

	freeifaddrs(ifap);

	TEST_START("freeifaddrs(NULL) is a no-op");
	freeifaddrs(NULL);
	TEST_DONE();
}
