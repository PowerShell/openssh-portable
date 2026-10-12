vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO Yubico/libfido2
    REF ${VERSION}
    SHA512 f168f1bac0b4ebf64a285d6f7b748cc3572e3280e8795e775471ddec059c4b255a80d79e5d93592a9e2a296ec1d959124a3c097e38a9ff203a34a9ccfefc6b66
    HEAD_REF master
    PATCHES
        "fix_cmakelists.patch"
        "modify_output_name.patch"
)

string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "static" LIBFIDO2_BUILD_STATIC)
string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "dynamic" LIBFIDO2_BUILD_SHARED)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_EXAMPLES=OFF
        -DBUILD_MANPAGES=OFF
        -DBUILD_STATIC_LIBS=${LIBFIDO2_BUILD_STATIC}
        -DBUILD_SHARED_LIBS=${LIBFIDO2_BUILD_SHARED}
        -DBUILD_TOOLS=OFF
 )

vcpkg_cmake_install()
vcpkg_copy_pdbs()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
