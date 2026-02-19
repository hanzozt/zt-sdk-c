add_executable(zt-ncat zt-ncat.c)
target_link_libraries(zt-ncat PUBLIC zt)

add_executable(zt-socket-sample zt-fd-client.c)
target_link_libraries(zt-socket-sample PUBLIC zt)
