
/* removes first '/' for Windows paths that are unix styled. Ex: /c:/ab.cd */
#define sanitized_path(p) (((p)[0] == '/' && (p)[1] != '\0' && (p)[2] == ':')? (p)+1 : (p))

__time64_t w32ftime_to_time64(FILETIME * ftime);
unsigned short w32attr_to_xmode(int attr);
int wstat64_s(const wchar_t *path, struct _stat64 *buf);
