set(PROGRAM_NAME pico_w_webserver)

set(MAKE_FS_DATA_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/external/makefsdata)

if (NOT EXISTS ${MAKE_FS_DATA_SCRIPT})
        file(DOWNLOAD
                https://raw.githubusercontent.com/krzmaz/lwip/e15654409d14a238aec5ed4bd5516063938c9345/src/apps/http/makefsdata/makefsdata
                ${MAKE_FS_DATA_SCRIPT}
                )
endif()

# Make sure TinyUSB can find tusb_config.h

message("Running makefsdata script")
execute_process(COMMAND
        perl ${MAKE_FS_DATA_SCRIPT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        ECHO_OUTPUT_VARIABLE
        ECHO_ERROR_VARIABLE
        )
file(RENAME fsdata.c my_fsdata.c)

add_executable(${PROGRAM_NAME}
        main.cpp
        ssi.cpp
        cgi.cpp
        adb_utils.c
        )

target_include_directories(${PROGRAM_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_include_directories(${PROGRAM_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls)

set(MBEDTLS_LIB_PATH ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls)
set(MBEDTLS_INCLUDE_PATH ${CMAKE_CURRENT_LIST_DIR}/../lib/mbedtls/include)
target_include_directories(${PROGRAM_NAME} PRIVATE ${MBEDTLS_INCLUDE_PATH})
target_compile_definitions(${PROGRAM_NAME} PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        )
        

target_link_libraries(${PROGRAM_NAME}
        pico_cyw43_arch_lwip_threadsafe_background
        pico_lwip_http
        pico_stdlib
        hardware_adc
        tinyusb_device
        tinyusb_host
        tinyusb_board
        pico_lwip_mbedtls
        pico_mbedtls
        )

pico_enable_stdio_usb(${PROGRAM_NAME} 0)
pico_enable_stdio_uart(${PROGRAM_NAME} 1)

suppress_tinyusb_warnings()

pico_add_extra_outputs(${PROGRAM_NAME})




# pull in common dependencies


# create map/bin/hex/uf2 file etc.
pico_add_extra_outputs(${PROGRAM_NAME})