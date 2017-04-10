/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Compatibility header to give us file permission functionality on Win32
*/

enum WELL_KNOWN_ACCOUNT_TYPE {
	WinBuiltinAdministrators = 0x001,
	WinLocalSystem = 0x002,
	Other = 0x004,
};

int w32_secure_file_permission(const char *, struct passwd *, DWORD);