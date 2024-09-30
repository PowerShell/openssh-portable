/*
 * Copyright (c) 2005 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"
#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "openbsd-compat/sys-queue.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "channels.h"
#include "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#if defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#include <linux/if.h>
#endif

#if defined(SYS_RDOMAIN_LINUX)
char *
sys_get_rdomain(int fd)
{
	char dev[IFNAMSIZ + 1];
	socklen_t len = sizeof(dev) - 1;

	if (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error("%s: cannot determine VRF for fd=%d : %s",
		    __func__, fd, strerror(errno));
		return NULL;
	}
	dev[len] = '\0';
	return strdup(dev);
}

int
sys_set_rdomain(int fd, const char *name)
{
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error("%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    __func__, fd, name, strerror(errno));
		return -1;
	}
	return 0;
}

int
sys_valid_rdomain(const char *name)
{
	int fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return 0;
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
}
#elif defined(SYS_RDOMAIN_XXX)
/* XXX examples */
char *
sys_get_rdomain(int fd)
{
	return NULL;
}

int
sys_set_rdomain(int fd, const char *name)
{
	return -1;
}

int
valid_rdomain(const char *name)
{
	return 0;
}

void
sys_set_process_rdomain(const char *name)
{
	fatal("%s: not supported", __func__);
}
#endif /* defined(SYS_RDOMAIN_XXX) */

/*
 * This is the portable version of the SSH tunnel forwarding, it
 * uses some preprocessor definitions for various platform-specific
 * settings.
 *
 * SSH_TUN_LINUX	Use the (newer) Linux tun/tap device
 * SSH_TUN_FREEBSD	Use the FreeBSD tun/tap device
 * SSH_TUN_COMPAT_AF	Translate the OpenBSD address family
 * SSH_TUN_PREPEND_AF	Prepend/remove the address family
 */

/*
 * System-specific tunnel open function
 */

#if defined(SSH_TUN_LINUX)
#include <linux/if_tun.h>
#define TUN_CTRL_DEV "/dev/net/tun"

int
sys_tun_open(int tun, int mode, const char* tunnel_options, char **ifname)
{
	struct ifreq ifr;
	int fd = -1;
	const char *name = NULL;

	if (ifname != NULL)
		*ifname = NULL;
	if ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug("%s: failed to open tunnel control device \"%s\": %s",
		    __func__, TUN_CTRL_DEV, strerror(errno));
		return (-1);
	}

	bzero(&ifr, sizeof(ifr));

	if (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} else {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	if (tun != SSH_TUNID_ANY) {
		if (tun > SSH_TUNID_MAX) {
			debug("%s: invalid tunnel id %x: %s", __func__,
			    tun, strerror(errno));
			goto failed;
		}
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), name, tun);
	}

	if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug("%s: failed to configure tunnel (mode %d): %s", __func__,
		    mode, strerror(errno));
		goto failed;
	}

	if (tun == SSH_TUNID_ANY)
		debug("%s: tunnel mode %d fd %d", __func__, mode, fd);
	else
		debug("%s: %s mode %d fd %d", __func__, ifr.ifr_name, mode, fd);

	if (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	return (fd);

 failed:
	close(fd);
	return (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#include <sys/socket.h>
#include <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

int
sys_tun_open(int tun, int mode, const char* tunnel_options, char **ifname)
{
	struct ifreq ifr;
	char name[100];
	int fd = -1, sock;
	const char *tunbase = "tun";
#if defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	int flag;
#endif

	if (ifname != NULL)
		*ifname = NULL;

	if (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug("%s: no layer 2 tunnelling support", __func__);
		return (-1);
#else
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	if (tun <= SSH_TUNID_MAX) {
		snprintf(name, sizeof(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} else if (tun == SSH_TUNID_ANY) {
		for (tun = 100; tun >= 0; tun--) {
			snprintf(name, sizeof(name), "/dev/%s%d",
			    tunbase, tun);
			if ((fd = open(name, O_RDWR)) >= 0)
				break;
		}
	} else {
		debug("%s: invalid tunnel %u\n", __func__, tun);
		return (-1);
	}

	if (fd < 0) {
		debug("%s: %s open failed: %s", __func__, name,
		    strerror(errno));
		return (-1);
	}

	/* Turn on tunnel headers */
#if defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
	flag = 1;
	if (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug("%s: ioctl(%d, TUNSIFHEAD, 1): %s", __func__, fd,
		    strerror(errno));
		close(fd);
	}
#endif

	debug("%s: %s mode %d fd %d", __func__, name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", tunbase, tun);
	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		goto failed;
	if ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			goto failed;
	}

	if (ifname != NULL && (*ifname = strdup(ifr.ifr_name)) == NULL)
		goto failed;

	close(sock);
	return (fd);

 failed:
	if (fd >= 0)
		close(fd);
	if (sock >= 0)
		close(sock);
	debug("%s: failed to set %s mode %d: %s", __func__, name,
	    mode, strerror(errno));
	return (-1);
}
#endif /* SSH_TUN_FREEBSD */

/*
 * System-specific channel filters
 */

#if defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

int
sys_tun_infilter(struct ssh *ssh, struct Channel *c, char *buf, int _len)
{
	int r;
	size_t len;
	char *ptr = buf;
#if defined(SSH_TUN_PREPEND_AF)
	char rbuf[CHAN_RBUF];
	struct ip iph;
#endif
#if defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	/* XXX update channel input filter API to use unsigned length */
	if (_len < 0)
		return -1;
	len = _len;

#if defined(SSH_TUN_PREPEND_AF)
	if (len <= sizeof(iph) || len > sizeof(rbuf) - 4)
		return -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, sizeof(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#elif defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	if (len <= 4)
		return -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	if ((r = sshbuf_put_string(c->input, ptr, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	return (0);
}

u_char *
sys_tun_outfilter(struct ssh *ssh, struct Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	int r;

	/* XXX new API is incompatible with this signature. */
	if ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if (*dlen < sizeof(af))
		return (NULL);
	buf = *data;

#if defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= sizeof(af);
	buf = *data + sizeof(af);
#elif defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	return (buf);
}
#endif /* SSH_TUN_FILTER */

#if defined(SSH_TUN_TAP_WINDOWS_V9)

#if defined(WIN32) || defined(WIN64)

////////////////////////////////////////////////////////////////////
//
//  Experimental support for Windows Tunnel (TAP-Windows V9 driver)
//
// This part adds a quite rude support to tunnel device on Windows,
// so you can use "-w" options on Windows.
// It uses TAP-Windows V9 driver. At the moment (2024/09/20) this
// code has been tested only on Windows10-19045 and TAP-Windows
// driver 9.23.3.601 (you can download it here:
// https://build.openvpn.net/downloads/releases/tap-windows-9.23.3-I601-Win10.exe).
// Only "ethernet" tunnel mode is supported, since TAP-Windows
// driver doesn't implement TUN (point-to-point). Because of this,
// "-o Tunnel=ethernet" command line option or equivalent configuration
// item must be set. Here's the typical command invocation:
// 
// ssh -o Tunnel=ethernet user@host -w any
// 
// One can also specify an adapter index (the ifIndex field
// as shown, for example, in powershell's "get-netadapter"
// output) to force the use of a particular TAP instance.
// 
// Here's what the function "sys_tun_open" does:
// - It checks if the selected tunnel mode is "ethernet".
// - It explores the list of adapters returned by
// GetAdaptersAddresses Windows function (from IPHLPAPI subsystem).
// - If a index is specified, the function takes the adaper
// whose IfIndex match the given value. If the index is not
// specified ("any"), the function takes the adapters whose
// friendly name starts with "SSH Tunnel" (case insensitive)
// or whatever is configured (see "TunnelOptions" configuration
// item).
// - If a matching adapter if found, the function tries to open
// and activate it. In case of failure, it takes the next matching
// adapter.
// - The file descriptor of the first successful open is resturned,
// or -1 if there are no free adapters.
// 
// The function relies on the presence of a certain number of
// instances of the TAP-Windows driver, all with friendly names
// starting with "SSH Tunnel". During installation, these instances
// must be generated by installing the driver as many times as
// necessary. Each instance must be renamed according to the
// convention (e.g. "SSH Tunnel 1", "SSH Tunnel 2" ...).
// You can change the default prefix via "TunnelOptions"
// configuration item. NOTE: Only ANSI characters are allowed.
// 
// NOTE: TAP devices must be opened in a special way. In order to
// make the device interoperate with the existing SSH framework
// (based on UNIX' "file descriptor" paradigm), we added
// a special flag "O_SYSTEM" for "open". This is because the way
// "open" ("w32_open") calls "CreateFile" is not suitable for TAP
// devices. In particular, FILE_ATTRIBUTE_SYSTEM must be provided,
// and FILE_FLAG_BACKUP_SEMANTICS must not appear. The new flag
// instructs "open" to respect this rule.
// 
////////////////////////////////////////////////////////////////////

#include <winioctl.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")

#include "ssh.h"

//#include "readconf.h"
//extern Options options;

/* From OpenVPN tap driver, common.h */
#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE (10, METHOD_BUFFERED)


#define SSH_BASE_ADAPTER_FRIENDLY_NAME "SSH Tunnel"

static int open_adapter(const char* name)
{
	int fd = -1;
	char *netdev = NULL;
	int ok = 0;

	debug(" Trying adapter %s", name);


	netdev = (char*)malloc(strlen(name) + 30 /* 16 at least */);
	if (netdev == NULL) {
		error("Out of memory while creating adapter device name");
		goto FAIL;
	}

	sprintf(netdev, "\\\\.\\Global\\%s.tap", name);

	/*
	HANDLE h = CreateFile(netdev, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING,
	                      FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
	*/

	// Open device. Non-standard flag O_SYSTEM forces FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED
	// in CreateFile.
	// NOTE: "open" internally modifies paths (e.g. converts "\" in "/"
	// and much more). Windows seems to understand anyway, fortunately.
	
	fd = open(netdev, O_RDWR | O_EXCL | O_SYSTEM);

	if (fd < 0) {
		goto FAIL;
	}

	HANDLE h = w32_fd_to_handle(fd);
	DWORD len = 0;

	// For debugging purpose, we print the MAC.
	// It is also a way to make sure that the device is a TAP.

	unsigned char mac[6];

	if (DeviceIoControl(h, TAP_IOCTL_GET_MAC, &mac, sizeof(mac), &mac, sizeof(mac), &len, NULL)) {
		debug(" Adapter's MAC: %02x-%02x-%02x-%02x-%02x-%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	else {
		// We could survive (we don't actually need to know MAC),
		// but a failure here is a symptom of more general
		// problems, or perhaps the device is not a real TAP, but something else.
		error("Could not get adapter MAC, error 0x%08x", GetLastError());
		goto FAIL;
	}

	// Turn adapter on. If we didn't do the device couldn't work (e.g. ReadFileEx would fail).

	ULONG flag = 1;

	if (DeviceIoControl(h, TAP_IOCTL_SET_MEDIA_STATUS, &flag, sizeof(flag), &flag, sizeof(flag), &len, NULL) == 0) {
		error("Could not activate adapter, error 0x%08x", GetLastError());
		goto FAIL;
	}

	ok = 1;

FAIL:
	if (!ok) {
		if (fd >= 0) {
			close(fd);
			fd = -1;
		}
	}
	if (netdev != NULL) {
		free(netdev);
	}
	return fd;
}

static int lookup_and_open_tap_instance(int tun, char** ifname, const char *prefix)
{
	DWORD rv;
	ULONG sz = 0;
	ULONG new_sz = 0x4000;
	PIP_ADAPTER_ADDRESSES result = NULL;
	int tun_fd = -1;
	PWCHAR match = NULL;
	size_t match_len = 0;
	int ok = 0;
	
	if (prefix == NULL) {
		prefix = SSH_BASE_ADAPTER_FRIENDLY_NAME;
	}

	match_len = mbstowcs(NULL, prefix, 0);
	if (match_len == (size_t)(-1)) {
		error("Bad adapter name prefix: \"%s\"", prefix);
		goto FAIL;
	}
	match = (PWCHAR)malloc((match_len + 1) * sizeof(*match));
	if (match == NULL) {
		error("Out of memory while creating adapter name");
		goto FAIL;
	}
	match_len = mbstowcs(match, prefix, match_len + 1);

	// if tun == SSH_TUNID_ANY:
	// Looking for a free TUN/TAP instance.
	// We should create some TUN/TAP instances devoted to SSH,
	// and choose a recognizable "frendly name" for them,
	// otherwise whe could disturb (or be distubed by)
	// other applications (e.g. OpenVPN).
	// So, we'll look for the first free adapter whose frendly name
	// starts with "SSH Tunnel" (or whatever is configured).
	// TODO: Add a configuration item to change the string.
	// if tun != SSH_TUNID_ANY:
	// We got an adapter IfIndex directly from options, we have just
	// to check if it's a TUN/TAP instance.
	//
	// Anyway, we explore the list of IP_ADAPTER_ADDRESSES objects
	// and try to open the device instance of first one whose
	// FiendlyName or IfIndex match. If the device is busy or not working,
	// we try the next objects.
	// 


	if (tun != SSH_TUNID_ANY) {
		debug("Exploring network adapter list, looking for IfIndex %d", tun);
	}
	else {
		debug("Exploring network adapter list, looking for a FriendlyName matching \"%ws.*\"", match);
	}

	for (;;) {
		if (sz < new_sz) {
			if (result != NULL) {
				free(result);
			}
			sz = new_sz;
			result = (PIP_ADAPTER_ADDRESSES)malloc(sz);
			if (result == NULL) {
				error("Out of memory while reading adapter list");
				goto FAIL;
			}
		}
		rv = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX, NULL, result, &new_sz);
		if (rv == ERROR_SUCCESS) {
			break;
		}
		if (rv != ERROR_BUFFER_OVERFLOW) {
			error("Could not read adapter list, error 0x%08x", (unsigned int)rv);
			goto FAIL;
		}
	}

	PIP_ADAPTER_ADDRESSES addr;
	int no_match = 1;

	for (addr = result; addr != NULL; addr = addr->Next) {
		
		int match_found = 0;

		debug3(" Adapter %lu: Name=\"%s\", FriendlyName=\"%ws\", Description=\"%ws\"", addr->IfIndex, addr->AdapterName, addr->FriendlyName, addr->Description);

		if (tun != SSH_TUNID_ANY) {
			if (addr->IfIndex == (IF_INDEX)tun) {
				match_found = 1;
			}
		}
		else {
			if (_wcsnicmp(addr->FriendlyName, match, match_len) == 0) {
				match_found = 1;
			}
		}

		if (match_found) {
			
			no_match = 0;

			tun_fd = open_adapter(addr->AdapterName);

			if (tun_fd >= 0 || tun != SSH_TUNID_ANY) {
				break;
			}
		}
	}

	if (no_match) {
		debug("No matching adapter found");
	}

	if (tun_fd != -1 && ifname != NULL) {
		*ifname = strdup(addr->AdapterName);
		if (*ifname == NULL) {
			error("Out of memory while storing adapter name");
			goto FAIL;
		}
	}

	ok = 1;

FAIL:

	if (match != NULL) {
		free(match);
	}

	if (result != NULL) {
		free(result);
	}

	if (!ok) {
		if (ifname != NULL && *ifname != NULL) {
			free(*ifname);
		}
		if (tun_fd != -1) {
			close(tun_fd);
			tun_fd = -1;
		}
	}

	return tun_fd;
}

int
sys_tun_open(int tun, int mode, const char *tun_options, char** ifname)
{
	int tun_fd = -1;
	const char *prefix = NULL;

	prefix = tun_options;

	if (ifname != NULL) {
		*ifname = NULL;
	}

	if (mode != SSH_TUNMODE_ETHERNET) {
		// Sorry, TUN/TAP for Windows is actually TAP only.
		// TODO: Simulate Point-to-point (== TUN)
		error("Only ethernet mode tunnel interfaces (a.k.a. TAP) are supported on this platform");
		goto FAIL;
	}

	tun_fd = lookup_and_open_tap_instance(tun, ifname, prefix);

FAIL:
	return tun_fd;
}

#else

#error SSH_TUN_TAP_WINDOWS_V9 option is valid only on Windows

#endif

#endif // SSH_TUN_TAP_WINDOWS_V9

