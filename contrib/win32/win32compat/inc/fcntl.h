

#pragma once

/*fcntl commands*/
#define F_GETFL 0x1
#define F_SETFL 0x2
#define F_GETFD 0x4
#define F_SETFD 0x8

/*fd flags*/
#define FD_CLOEXEC 0x1


#define O_RDONLY      0x0000  // open for reading only
#define O_WRONLY      0x0001  // open for writing only
#define O_RDWR        0x0002  // open for reading and writing
#define O_ACCMODE	  0x0003
#define O_APPEND      0x0008  // writes done at eof

#define O_CREAT       0x0100  // create and open file
#define O_TRUNC       0x0200  // open and truncate
#define O_EXCL        0x0400  // open only if file doesn't already exist

#define O_TEXT        0x4000  /* file mode is text (translated) */
#define O_BINARY      0x8000  /* file mode is binary (untranslated) */
#define O_WTEXT       0x10000 /* file mode is UTF16 (translated) */
#define O_U16TEXT     0x20000 /* file mode is UTF16 no BOM (translated) */
#define O_U8TEXT      0x40000 /* file mode is UTF8  no BOM (translated) */

#define O_NOCTTY      0x80000 /* TODO - implement this if it makes sense on Windows*/

#define F_OK 0


int w32_fcntl(int fd, int cmd, ... /* arg */);
#define fcntl(a,b,...)		w32_fcntl((a), (b),  __VA_ARGS__)

#define open w32_open
int w32_open(const char *pathname, int flags, ...);

void* w32_fd_to_handle(int fd);
int w32_allocate_fd_for_handle(void* h, int is_sock);
