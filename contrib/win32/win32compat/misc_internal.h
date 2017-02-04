#define PATH_MAX MAX_PATH

#define GOTO_CLEANUP_IF(_cond_,_err_) do {  \
    if ((_cond_)) {                         \
        hr = _err_;                         \
        goto cleanup;                       \
    }                                       \
} while(0)

/* removes first '/' for Windows paths that are unix styled. Ex: /c:/ab.cd */
char * sanitized_path(const char *);

void w32posix_initialize();
void w32posix_done();

char* w32_programdir();

void convertToBackslash(char *str);
void convertToForwardslash(char *str);