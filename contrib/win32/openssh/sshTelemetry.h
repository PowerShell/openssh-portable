#pragma once

// sends authentication type and status
void send_auth_telemetry(const int status, const char* auth_type);

// sends crypto information like cipher, kex, and mac
void send_encryption_telemetry(const char* direction, 
	const char* cipher, const char* kex, const char* mac, 
	const char* comp, const char* host_key, 
	const char** cproposal, const char** sproposal);

// sends status if using key-based auth
void send_pubkey_telemetry(const char* pubKeyStatus);

// sends shell configuration and if pty session is used
void send_shell_telemetry(const int pty, const int shell_type);

// sends signing status if using key-based auth
void send_pubkey_sign_telemetry(const char* pubKeySignStatus);

// sends connection status from ssh client
void send_ssh_connection_telemetry(const char* conn);

// sends ports and auth methods configured by sshd
void send_sshd_config_telemetry(const int num_auth_methods, 
	const char** auth_methods, const unsigned int num_ports, 
	const int ports[]);

// sends version and peer version from ssh & sshd
void send_ssh_version_telemetry(const char* ssh_version,
	const char* peer_version, const char* remote_protocol_supported);
