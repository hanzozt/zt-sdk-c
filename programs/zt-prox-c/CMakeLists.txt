include(FindPkgConfig)
find_package(PkgConfig)
pkg_check_modules(STC REQUIRED IMPORTED_TARGET stc)

add_executable(zt-prox-c proxy.c
        main.cpp
        proxy.h)


target_link_libraries(zt-prox-c
        PUBLIC zt
        CLI11::CLI11
        PkgConfig::STC
)

if (MSVC)
    target_link_libraries(zt-prox-c PUBLIC shlwapi)
endif (MSVC)
target_include_directories(zt-prox-c PRIVATE ${zt-sdk_SOURCE_DIR}/inc_internal)

set(ZITI_ARCHIVE_NAME "zt-prox-c-${CPACK_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}.${archive_sfx}")

add_custom_target(zt-prox-c-pack
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${ZITI_ARCHIVE_NAME}
        DEPENDS zt-prox-c
        COMMAND ${ZIP} ${ZIP_OPTS} ${ZITI_ARCHIVE_NAME} $<TARGET_FILE:zt-prox-c>
        )
