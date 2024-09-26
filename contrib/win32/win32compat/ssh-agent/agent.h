#include <Windows.h>
#include <stdio.h>
#include "Debug.h"
#include "misc_internal.h"

#define MAX_MESSAGE_SIZE 256 * 1024

#define SSH_AGENT_ROOT SSH_REGISTRY_ROOT L"\\Agent"
#define SSH_KEYS_KEY L"Keys"
#define SSH_KEYS_ROOT SSH_AGENT_ROOT L"\\" SSH_KEYS_KEY
#define SSH_PKCS11_PROVIDERS_KEY L"PKCS11_Providers"
#define SSH_PKCS11_PROVIDERS_ROOT SSH_AGENT_ROOT L"\\" SSH_PKCS11_PROVIDERS_KEY
/* Maximum number of recorded session IDs/hostkeys per connection */
#define AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#define AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#define AGENT_MAX_DEST_CONSTRAINTS	1024

#define HEADER_SIZE 4

struct hostkey_sid {
	struct sshkey *key;
	struct sshbuf *sid;
	int forwarded;
};

struct agent_connection {
	OVERLAPPED ol;
	HANDLE pipe_handle;
	HANDLE client_impersonation_token;
	HANDLE client_process_handle;
	struct {
		DWORD num_bytes;
		DWORD transferred;
		char buf[MAX_MESSAGE_SIZE];
		DWORD buf_size;
	} io_buf;
	enum {
		LISTENING = 0,
		READING_HEADER,
		READING,
		WRITING,
		DONE
	} state;
	enum { /* retain this order */
		UNKNOWN = 0,
		NONADMIN_USER, /* client is running as a nonadmin user */
		ADMIN_USER, /* client is running as admin */
		SYSTEM, /* client is running as System */
		SERVICE, /* client is running as LS or NS */
	} client_type;
	
	size_t nsession_ids;
	struct hostkey_sid *session_ids;
};

void agent_connection_on_io(struct agent_connection*, DWORD, OVERLAPPED*);
void agent_connection_on_error(struct agent_connection* , DWORD);
void agent_connection_disconnect(struct agent_connection*);

void agent_start(BOOL);
void agent_process_connection(HANDLE);
void agent_shutdown();
void agent_cleanup_connection(struct agent_connection*);
void agent_initialize_allow_list();
