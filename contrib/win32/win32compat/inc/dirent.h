// direntry functions in Windows platform like Ubix/Linux
// opendir(), readdir(), closedir().
// 	NT_DIR * nt_opendir(char *name) ;
// 	struct nt_dirent *nt_readdir(NT_DIR *dirp);
// 	int nt_closedir(NT_DIR *dirp) ;

#ifndef __DIRENT_H__
#define __DIRENT_H__

#include <direct.h>
#include <io.h>
#include <fcntl.h>

// Windows directory structure content
//struct dirent {
//	char *d_name ; // name of the directory entry
//	int  d_ino; // UNIX inode
//	//unsigned attrib ; // its attributes
//};

struct dirent {
	int            d_ino;       /* Inode number */
	//off_t        d_off;       /* Not an offset; see below */
	unsigned short d_reclen;    /* Length of this record */
	unsigned char  d_type;      /* Type of file; not supported
								by all filesystem types */
	char           d_name[256]; /* Null-terminated filename */
};

typedef struct DIR_ DIR;

DIR * opendir(const char *name);
int closedir(DIR *dirp);
struct dirent *readdir(void *avp);

#endif