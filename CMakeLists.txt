cmake_minimum_required(VERSION 2.8)
project(gmcm)

SET (ENV "X86")
# SET (ENV "ARM")
# SET(CMAKE_VERBOSE_MAKEFILE on)
SET(debug -g)

SET(SDF 1)

IF (${ENV} STREQUAL "X86")
SET (CMAKE_C_COMPILER "/home/ngos/toolchain/1809/gcc-4.9.2-x86_64-unknown-linux-gnu/bin/x86_64-unknown-linux-gnu-gcc")
SET (CMAKE_CXX_COMPILER "/home/ngos/toolchain/1809/gcc-4.9.2-x86_64-unknown-linux-gnu/bin/x86_64-unknown-linux-gnu-g++")
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
find_library(gm_crypto crypto external_lib/${LIB_DIR})
find_library(gm_ssl ssl external_lib/${LIB_DIR})
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
target_link_libraries(gmcmrpc  dl m z ${gm_crypto} ${gm_ssl})

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
"server/src/*.cpp"
"server/src/*.h"
"server/src/*/*.cpp"
"server/src/*/*.h"
)

add_executable(gmcmserver ${server_src_file})
set_target_properties(gmcmserver PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories(gmcmserver PUBLIC rpc/include)
target_include_directories(gmcmserver PUBLIC external_include)
target_include_directories(gmcmserver PUBLIC tools)
target_link_libraries(gmcmserver gmcmrpc gmcmalg ${libhiredis})
target_link_libraries(gmcmserver cjson m dl)
set_target_properties(gmcmserver PROPERTIES COMPILE_FLAGS "-Wno-maybe-uninitialized")


file(GLOB alg_src_file CONFIGURE_DEPENDS
    "alg/src/*.cpp"
    "alg/src/*.h"
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
target_link_libraries(gmcmalg  ${gm_crypto} ${gm_ssl} dl)


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
target_include_directories(testPjst PUBLIC external_include)
target_link_libraries(testPjst cjson)

add_executable(testSdf gtest/testSdf.cpp)
target_include_directories(testSdf PUBLIC alg/include)
target_include_directories(testSdf PUBLIC tools)
target_link_libraries(testSdf gmcmalg)

add_executable(testCert gtest/testCert.cpp)
target_include_directories(testCert PUBLIC alg/include)
target_include_directories(testCert PUBLIC tools)
target_link_libraries(testCert gmcmalg)

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
    "rpc/include/util/tc_logger.h"
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

    "rpc/src/tc_ex.cpp"
    "rpc/src/tc_common.cpp"
    "rpc/src/tc_thread.cpp"
    "rpc/src/tc_socket.cpp"
    "rpc/src/tc_logger.cpp"
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

    "rpc/src/asm/${LIB_DIR}/*.S"
)

add_library(
    gmcmsdk
    SHARED
    ${sdk_src_file}
)
target_include_directories(gmcmsdk PUBLIC rpc/include)
target_include_directories(gmcmsdk PUBLIC tools)
set_target_properties(gmcmsdk PROPERTIES COMPILE_FLAGS " -DTARS_SSL=0")

add_executable(gmcmSdkClient client/simpleClient/simpleClient.cpp)
target_link_libraries(gmcmSdkClient gmcmsdk)
target_include_directories(gmcmSdkClient PUBLIC tools)


set(INSTALL_SERVER_PATH "/gmcm/server/")

set(INSTALL_ALG_HEADER_PATH "/gmcm/alg")
set(INSTALL_ALG_LIB_PATH "/gmcm/alg/lib/")

set(INSTALL_SDK_HEADER_PATH "/gmcm/sdk")
set(INSTALL_SDK_LIB_PATH "/gmcm/sdk/lib/")

set(INSTALL_LIB_PATH "/lib/")
set(INSTALL_TEST_PATH "/gmcm/test/")

install(TARGETS gmcmserver DESTINATION ${INSTALL_SERVER_PATH})
install(TARGETS gmcmrpc DESTINATION ${INSTALL_LIB_PATH})

install(TARGETS gmcmalg DESTINATION ${INSTALL_LIB_PATH})
install(TARGETS gmcmalg DESTINATION ${INSTALL_ALG_LIB_PATH})
install(DIRECTORY "alg/include" DESTINATION ${INSTALL_ALG_HEADER_PATH})

install(TARGETS gmcmsdk DESTINATION ${INSTALL_LIB_PATH})
install(TARGETS gmcmsdk DESTINATION ${INSTALL_SDK_LIB_PATH})
install(DIRECTORY "client/include" DESTINATION ${INSTALL_SDK_HEADER_PATH})
