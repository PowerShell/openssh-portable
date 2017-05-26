#pragma once
void socket_tests();
void file_tests();
void miscellaneous_tests();

char *dup_str(char *inStr);
void delete_dir_recursive(char *full_dir_path);

#define ASSERT_HANDLE(handle,retValue) \
{ \
	retValue = ((handle != INVALID_HANDLE_VALUE) && (handle != NULL)) ? 0 : -1; \
	ASSERT_INT_EQ(retValue, 0); \
}
