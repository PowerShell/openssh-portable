
#ifndef AUTHCONFIG_H
#define AUTHCONFIG_H

#define DEFAULT_AUTH_PROVIDER "default"

typedef struct {
	char *authProvider;
} AuthConfig;

void	initialize_auth_config(AuthConfig *);
void	load_auth_config(const char *filename, AuthConfig *authConfig);

#endif				/* AUTHCONFIG_H */
