/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* private stat.h (all code relying on POSIX wrapper should include this version
* instead of the one in Windows SDK. 
*/
#pragma once
#include "types.h"

/* flags COPIED FROM STAT.H
 */
#define _S_IFMT   0xF000 // File type mask
#define _S_IFDIR  0x4000 // Directory
#define _S_IFCHR  0x2000 // Character special
#define _S_IFIFO  0x1000 // Pipe
#define _S_IFREG  0x8000 // Regular
#define _S_IREAD  0x0100 // Read permission, owner
#define _S_IWRITE 0x0080 // Write permission, owner
#define _S_IEXEC  0x0040 // Execute/search permission, owner
#define _S_IFLNK  0xA000 // symbolic link
#define _S_IFSOCK 0xC000 // socket

#define S_ISLNK(mode)	(((mode) & S_IFMT) == S_IFLNK)

#define S_IFMT   _S_IFMT
#define S_IFDIR  _S_IFDIR
#define S_IFCHR  _S_IFCHR
#define S_IFREG  _S_IFREG
#define S_IREAD  _S_IREAD
#define S_IWRITE _S_IWRITE
#define S_IEXEC  _S_IEXEC
#define S_IFLNK  _S_IFLNK
#define S_IFSOCK _S_IFSOCK

 /* TODO - is this the right place for these defs ?*/
# define S_ISUID            0x800 
# define S_ISGID            0x400

int w32_fstat(int fd, struct w32_stat *buf);
#define fstat(a,b)	w32_fstat((a), (b))

int w32_stat(const char *path, struct w32_stat *buf);
#define stat w32_stat
#define lstat w32_stat

int w32_mkdir(const char *pathname, unsigned short mode);
#define mkdir w32_mkdir

int w32_chmod(const char *, mode_t);
#define chmod w32_chmod

struct w32_stat {
	dev_t     st_dev;     /* ID of device containing file */
	unsigned short     st_ino;     /* inode number */
	unsigned short    st_mode;    /* protection */
	short    st_nlink;   /* number of hard links */
	short     st_uid;     /* user ID of owner */
	short     st_gid;     /* group ID of owner */
	dev_t     st_rdev;    /* device ID (if special file) */
	__int64     st_size;    /* total size, in bytes */
	__int64    st_atime;   /* time of last access */
	__int64    st_mtime;   /* time of last modification */
	__int64    st_ctime;   /* time of last status change */
};


void strmode(mode_t mode, char *p);

