
#include "includes.h"
#include "authconfig.h"
#include "buffer.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Initializes the auth config to their default values. */

void
initialize_auth_config(AuthConfig *config)
{
	memset(config, 0, sizeof(*config));
	config->authProvider = DEFAULT_AUTH_PROVIDER;
}

/* Reads the auth configuration file. */

void
load_auth_config(const char *filename, AuthConfig *authConfig)
{
	char line[4096];
	FILE *f;

	debug("%s: filename %s", __func__, filename);
	if ((f = fopen(filename, "r")) == NULL) {
		return;
	}
	if (fgets(line, sizeof(line), f)) {
		memset(authConfig->authProvider, 0, strlen(authConfig->authProvider));
		strcpy(authConfig->authProvider, line);
	}
	fclose(f);
	debug("%s: done auth provider  = %s", __func__, authConfig->authProvider);
}
