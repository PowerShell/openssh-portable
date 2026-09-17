#pragma once

struct	sockaddr_un {
	short	sun_family;		/* AF_UNIX */
	/*
	 * larger than the traditional 108 - these paths are mapped onto
	 * named pipe names on Windows and deep profile paths are common
	 */
	char	sun_path[260];		/* path name (gag) */
};

