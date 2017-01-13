#ifndef COMPAT_PARAM_H
#define COMPAT_PARAM_H 1

typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef long long  off_t;
typedef unsigned int dev_t;

#undef NAME_MAX
#define NAME_MAX   255

#undef PATH_MAX
#define PATH_MAX   4096

#endif
