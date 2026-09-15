/* Windows compat shim for <sys/mount.h>.
 *
 * Upstream (commit 3e9c4ed3b) removed the #ifdef HAVE_SYS_MOUNT_H guard around
 * #include <sys/mount.h> in sftp-server.c, relying on configure to generate an
 * empty shim on platforms that lack the header (only DragonFlyBSD gets a real
 * redirect). Windows has no <sys/mount.h> and does not run configure, so this
 * intentionally empty shim satisfies the unconditional include. */
#pragma once
