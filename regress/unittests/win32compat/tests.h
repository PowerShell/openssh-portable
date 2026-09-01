#pragma once
void signal_tests();
void socket_tests();
void file_tests();
void miscellaneous_tests();
void pkcs11_cert_tests(void);

char *dup_str(char *inStr);
void delete_dir_recursive(char *full_dir_path);

#define ASSERT_HANDLE(handle) \
{\
	ASSERT_PTR_NE(handle, INVALID_HANDLE_VALUE); \
	ASSERT_PTR_NE(handle, 0); \
}
