add_executable(zt_mfa zt_mfa.cpp)
set_target_properties(zt_mfa PROPERTIES
        CXX_STANDARD 20
)

target_link_libraries(zt_mfa
        PUBLIC zt
        PRIVATE CLI11::CLI11
)

add_executable(jwt-auth jwt_auth.cpp)
set_target_properties(jwt-auth PROPERTIES
        CXX_STANDARD 20
)
target_link_libraries(jwt-auth zt CLI11::CLI11)