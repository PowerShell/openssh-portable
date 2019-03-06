#pragma once
#include <Windows.h>
#define RTLD_NOW 0

#define dlerror() GetLastError()

HMODULE dlopen(const char *filename, int flags);

int dlclose(HMODULE handle);

void * dlsym(HMODULE handle, const char *symbol);
