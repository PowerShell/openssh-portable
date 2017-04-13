/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Compatibility header to give us file permission functionality on Win32
*/

int w32_secure_file_permission(const char *, struct passwd *);