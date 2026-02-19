
add_executable(ztlib-server server.c)
target_link_libraries(ztlib-server PUBLIC zt)

#add_executable(forky forky-client.c)
#target_link_libraries(forky PUBLIC zt)

add_executable(zt-http-get zt-http-get.c)
target_link_libraries(zt-http-get PUBLIC zt)