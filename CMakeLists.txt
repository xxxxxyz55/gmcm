cmake_minimum_required(VERSION 2.8)
project(gmcm)

SET (ENV "X86")
# SET (ENV "ARM")
# SET(CMAKE_VERBOSE_MAKEFILE on) 
SET(SSL 0)
SET(STATIC_SSL on) #静态包含ssl
SET(debug -g)

SET(SDF 1)

IF (${ENV} STREQUAL "X86")
SET (CMAKE_C_COMPILER "gcc")
SET (CMAKE_CXX_COMPILER "g++")
SET (LIB_DIR x86)
ELSEIF (${ENV} STREQUAL "ARM")
SET (CMAKE_C_COMPILER "aarch64-linux-gnu-gcc")
SET (CMAKE_CXX_COMPILER "aarch64-linux-gnu-g++")
SET (CMAKE_AR "aarch64-linux-gnu-ar")
SET (LIB_DIR arm)
ENDIF()

SET (flags "${debug} -Wall -O2 -rdynamic -funwind-tables  -fPIC -Wunused-variable -fno-strict-aliasing")
SET (STACK_PROTECTOR "-fstack-protector-strong -fstack-protector-all")
SET (WARNNING "-Wall -Wformat -Werror=format-security -fexceptions")

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 ${flags} ${STACK_PROTECTOR} ${WARNNING}")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
SET(CMAKE_INSTALL_RPATH /lib)

ENABLE_LANGUAGE(ASM)
SET(CMAKE_ASM_FLAGS "-g  -Wall -O2 -fPIC")

link_directories(/lib)
if(STATIC_SSL)
find_library(gm_crypto libcrypto.a external_lib/${LIB_DIR} NO_DEFAULT_PATH)
find_library(gm_ssl libssl.a external_lib/${LIB_DIR} NO_DEFAULT_PATH)
else()
find_library(gm_crypto libcrypto.so.1.1 external_lib/${LIB_DIR} NO_DEFAULT_PATH)
find_library(gm_ssl libssl.so.1.1 external_lib/${LIB_DIR} NO_DEFAULT_PATH)
endif()
find_library(libhiredis hiredis external_lib/${LIB_DIR})

file(GLOB rpc_source_files CONFIGURE_DEPENDS
"rpc/src/asm/${LIB_DIR}/*.S"
"rpc/src/*.cpp"
"rpc/include/util/*.h"
)

add_library(
    gmcmrpc
    SHARED
    ${rpc_source_files}
)

target_include_directories(gmcmrpc PUBLIC rpc/include)
target_include_directories(gmcmrpc PUBLIC external_include/openssl)
target_link_libraries(gmcmrpc  pthread)
target_link_libraries(gmcmrpc  c)
target_link_libraries(gmcmrpc  m z)
if(SSL)
target_link_libraries(gmcmrpc dl ${gm_crypto} ${gm_ssl})
endif()
set_target_properties(gmcmrpc PROPERTIES COMPILE_FLAGS " -DTARS_SSL=${SSL}")


if (0)
add_library(
    gmcmrpc_static
    STATIC
    ${rpc_source_files}
)
target_include_directories(gmcmrpc_static PUBLIC rpc/include)
set_target_properties(gmcmrpc_static PROPERTIES OUTPUT_NAME "gmcmrpc")
set_target_properties(gmcmrpc PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(gmcmrpc_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
endif()

file(GLOB server_src_file CONFIGURE_DEPENDS
"server/*.cpp"
"server/*.h"
"server/*/*.cpp"
"server/*/*.h"
"server/*/*/*.cpp"
"server/*/*/*.h"
)

add_executable(gmcmserver ${server_src_file})
set_target_properties(gmcmserver PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories(gmcmserver PUBLIC rpc/include)
target_include_directories(gmcmserver PUBLIC external_include)
target_include_directories(gmcmserver PUBLIC tools)
target_link_libraries(gmcmserver gmcmrpc gmcmalg gmcmencode ${libhiredis})
target_link_libraries(gmcmserver m dl)
set_target_properties(gmcmserver PROPERTIES COMPILE_FLAGS "-Wno-maybe-uninitialized")
set_target_properties(gmcmserver PROPERTIES COMPILE_FLAGS " -DTARS_SSL=${SSL}")


file(GLOB alg_src_file CONFIGURE_DEPENDS
    "alg/src/*.cpp"
    "alg/src/*.h"
    "alg/src/gmssl/*.c"
    "alg/src/gmssl/*.h"
)

add_library(
    gmcmalg
    SHARED
    ${alg_src_file}
)

set_target_properties(gmcmalg PROPERTIES COMPILE_FLAGS "-fvisibility=hidden -DSDF=${SDF}")
target_include_directories(gmcmalg PUBLIC alg/include)
target_include_directories(gmcmalg PUBLIC tools)
target_include_directories(gmcmalg PUBLIC external_include/openssl)
target_include_directories(gmcmalg PUBLIC external_include/)
target_include_directories(gmcmalg PUBLIC rpc/include)
target_link_libraries(gmcmalg  ${gm_crypto} ${gm_ssl} dl pthread)

file(GLOB encode_src_file CONFIGURE_DEPENDS
    "encode/*/*.cpp"
    "encode/*/*.c"
    "encode/*/*.h"
)

add_library(
    gmcmencode
    SHARED
    ${encode_src_file}
)
set_target_properties(gmcmencode PROPERTIES COMPILE_FLAGS "-O3")

add_executable(testEventWait gtest/testEventWait.cpp)
target_include_directories(testEventWait PUBLIC tools)
target_link_libraries(testEventWait pthread)

add_executable(testObjInitCopy gtest/testObjInitCopy.cpp)
target_include_directories(testObjInitCopy PUBLIC tools)

add_executable(testUikey gtest/testUikey.cpp)
target_include_directories(testUikey PUBLIC alg/include)
target_link_libraries(testUikey gmcmalg)

add_executable(testPst gtest/testPst.cpp)
target_include_directories(testPst PUBLIC tools)

add_executable(testPjst gtest/testPjst.cpp)
target_include_directories(testPjst PUBLIC tools)
target_include_directories(testPjst PUBLIC rpc/include)
target_include_directories(testPjst PUBLIC external_include)
target_link_libraries(testPjst gmcmrpc)

add_executable(testSdf gtest/testSdf.cpp)
target_include_directories(testSdf PUBLIC alg/include)
target_include_directories(testSdf PUBLIC tools)
target_link_libraries(testSdf gmcmalg)

add_executable(testCert gtest/testCert.cpp)
target_include_directories(testCert PUBLIC alg/include)
target_include_directories(testCert PUBLIC tools)
target_link_libraries(testCert gmcmalg)

add_executable(testRpcLib gtest/testRpcLib.cpp)
target_include_directories(testRpcLib PUBLIC rpc/include)
target_link_libraries(testRpcLib gmcmrpc)

add_executable(testOrm gtest/testOrm.cpp)
target_include_directories(testOrm PUBLIC tools)

add_executable(testRandom gtest/testRandom.cpp)
target_include_directories(testRandom PUBLIC tools)
target_include_directories(testRandom PUBLIC alg/include)
target_link_libraries(testRandom gmcmalg)

add_executable(testSafeQueue gtest/testSafeQueue.cpp)
target_include_directories(testSafeQueue PUBLIC external_include)
target_include_directories(testSafeQueue PUBLIC tools)
target_include_directories(testSafeQueue PUBLIC rpc/include)
target_link_libraries(testSafeQueue pthread)

add_executable(testPerfConn gtest/testPerfConn.cpp)
target_include_directories(testPerfConn PUBLIC tools)
target_include_directories(testPerfConn PUBLIC encode)
target_include_directories(testPerfConn PUBLIC external_include)
target_include_directories(testPerfConn PUBLIC rpc/include)
target_link_libraries(testPerfConn ${libhiredis} pthread gmcmrpc cjson gmcmencode)

add_executable(testClv gtest/testClv.cpp)
target_include_directories(testClv PUBLIC tools)
target_include_directories(testClv PUBLIC encode)
target_link_libraries(testClv gmcmencode pthread )

file(GLOB sdk_src_file CONFIGURE_DEPENDS
    "client/sdk/*.cpp"
    "client/include/*.h"
    "rpc/include/util/tc_platform.h"
    "rpc/include/util/tc_ex.h"
    "rpc/include/util/tc_common.h"
    "rpc/include/util/tc_autoptr.h"
    "rpc/include/util/tc_thread.h"
    "rpc/include/util/tc_monitor.h"
    "rpc/include/util/tc_socket.h"
    "rpc/include/util/tc_timer.h"
    "rpc/include/util/tc_timeprovider.h"
    "rpc/include/util/tc_epoller.h"
    "rpc/include/util/tc_timeout_queue.h"
    "rpc/include/util/tc_network_buffer.h"
    "rpc/include/util/tc_http.h"
    "rpc/include/util/tc_clientsocket.h"
    "rpc/include/util/tc_port.h"
    "rpc/include/util/tc_coroutine.h"
    "rpc/include/util/tc_file.h"
    "rpc/include/util/tc_thread_mutex.h"
    "rpc/include/util/tc_spin_lock.h"
    "rpc/include/util/tc_thread_cond.h"
    "rpc/include/util/tc_thread_pool.h"
    "rpc/include/util/tc_cron.h"
    "rpc/include/util/tc_openssl.h"

    "rpc/src/tc_ex.cpp"
    "rpc/src/tc_common.cpp"
    "rpc/src/tc_thread.cpp"
    "rpc/src/tc_socket.cpp"
    "rpc/src/tc_timer.cpp"
    "rpc/src/tc_timeprovider.cpp"
    "rpc/src/tc_epoller.cpp"
    "rpc/src/tc_timeout_queue.cpp"
    "rpc/src/tc_network_buffer.cpp"
    "rpc/src/tc_http.cpp"
    "rpc/src/tc_clientsocket.cpp"
    "rpc/src/tc_port.cpp"
    "rpc/src/tc_coroutine.cpp"
    "rpc/src/tc_file.cpp"
    "rpc/src/tc_thread_mutex.cpp"
    "rpc/src/tc_spin_lock.cpp"
    "rpc/src/tc_thread_cond.cpp"
    "rpc/src/tc_thread_pool.cpp"
    "rpc/src/tc_cron.cpp"
    "rpc/src/tc_openssl.cpp"

    "rpc/src/asm/${LIB_DIR}/*.S"
    "encode/clv/*"
)

add_library(
    gmcmsdk
    SHARED
    ${sdk_src_file}
)
target_include_directories(gmcmsdk PUBLIC rpc/include)
target_include_directories(gmcmsdk PUBLIC external_include/openssl)
target_include_directories(gmcmsdk PUBLIC tools)
set_target_properties(gmcmsdk PROPERTIES COMPILE_FLAGS " -DTARS_SSL=${SSL}")
if(SSL)
target_link_libraries(gmcmsdk ${gm_crypto} ${gm_ssl} dl)
endif()
target_link_libraries(gmcmsdk pthread)

add_executable(gmcmSdkClient client/demo/simpleClient.cpp)
target_link_libraries(gmcmSdkClient gmcmsdk)
target_include_directories(gmcmSdkClient PUBLIC tools)

add_executable(gmcmHttpClient client/demo/httpClient.cpp)
target_link_libraries(gmcmHttpClient gmcmsdk)
target_include_directories(gmcmHttpClient PUBLIC external_include/openssl)
target_include_directories(gmcmHttpClient PUBLIC tools)
set_target_properties(gmcmHttpClient PROPERTIES COMPILE_FLAGS " -DTARS_SSL=${SSL}")



set(INSTALL_SERVER_PATH "/gmcm/server/")

set(INSTALL_ALG_HEADER_PATH "/gmcm/alg")
set(INSTALL_ALG_LIB_PATH "/gmcm/alg/lib/")

set(INSTALL_SDK_HEADER_PATH "/gmcm/sdk")
set(INSTALL_SDK_LIB_PATH "/gmcm/sdk/lib/")

set(INSTALL_LIB_PATH "/lib/")
set(INSTALL_TEST_PATH "/gmcm/test/")

install(TARGETS gmcmserver DESTINATION ${INSTALL_SERVER_PATH})
install(TARGETS gmcmrpc DESTINATION ${INSTALL_LIB_PATH})

install(TARGETS gmcmencode DESTINATION ${INSTALL_LIB_PATH})

install(TARGETS gmcmalg DESTINATION ${INSTALL_LIB_PATH})
install(TARGETS gmcmalg DESTINATION ${INSTALL_ALG_LIB_PATH})
install(DIRECTORY "alg/include" DESTINATION ${INSTALL_ALG_HEADER_PATH})

install(TARGETS gmcmsdk DESTINATION ${INSTALL_LIB_PATH})
install(TARGETS gmcmsdk DESTINATION ${INSTALL_SDK_LIB_PATH})
install(TARGETS gmcmHttpClient DESTINATION ${INSTALL_SERVER_PATH})
install(DIRECTORY "client/include" DESTINATION ${INSTALL_SDK_HEADER_PATH})
