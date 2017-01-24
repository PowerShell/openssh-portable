/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Win32 renamed POSIX APIs
*/
#pragma once
#include <Windows.h>
#include <stdio.h>
#include "defs.h"
#include "utf.h"
#include "sys\param.h"



void w32posix_initialize();
void w32posix_done();
char* w32_programdir();


/* 
 * these routines are temporarily defined here to allow transition 
 * from older POSIX wrapper to the newer one. After complete transition 
 * these should be gone or moved to a internal header.
 */
HANDLE w32_fd_to_handle(int fd);
int w32_allocate_fd_for_handle(HANDLE h, BOOL is_sock);
int sw_add_child(HANDLE child, DWORD pid);

/* temporary definitions to aid in transition */
#define sfd_to_handle(a) w32_fd_to_handle((a))

void convertToBackslash(char *str);
void convertToForwardslash(char *str);
