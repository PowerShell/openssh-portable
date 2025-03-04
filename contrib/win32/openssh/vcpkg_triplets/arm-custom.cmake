set(VCPKG_TARGET_ARCHITECTURE arm)

if(${PORT} MATCHES "zlib")
	set(VCPKG_CRT_LINKAGE static)
	set(VCPKG_LIBRARY_LINKAGE static)
else()
	set(VCPKG_CRT_LINKAGE dynamic)
	set(VCPKG_LIBRARY_LINKAGE dynamic)
endif()
