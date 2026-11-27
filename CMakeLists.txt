#
# nkey-firmware build configuration (https://brucencnp.com/nkey/ |
# https://github.com/BruceNCNP/nkey-firmware)
# Adapted from Pico FIDO (https://github.com/polhenarejos/pico-fido).
#
# Original Pico FIDO portions: Copyright (c) 2022 Pol Henarejos.
# nkey-firmware modifications: Copyright (c) BruceNCNP.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

cmake_minimum_required(VERSION 3.13)

set(USB_VID 0xBEEF)
set(USB_PID 0x0001)

if(ESP_PLATFORM)
    set(PICOKEYS_COMPONENTS fido)
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
else()
    if(NOT ENABLE_EMULATION)
        set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
        include(pico_sdk_import.cmake)
    endif()

    project(pico_fido C CXX ASM)

    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)

    add_executable(pico_fido)
endif()

include(pico-keys-sdk/cmake/options.cmake)

option(ENABLE_POWER_ON_RESET "Enable/disable power cycle on reset" ON)
configure_bool_option(
    ENABLE_POWER_ON_RESET
    ENABLE_POWER_ON_RESET
    "Power cycle on reset: \t enabled"
    "Power cycle on reset: \t disabled"
)

option(ENABLE_OATH_APP "Enable/disable OATH application" ON)
configure_bool_option(
    ENABLE_OATH_APP
    ENABLE_OATH_APP
    "OATH Application: \t\t enabled"
    "OATH Application: \t\t disabled"
)

option(ENABLE_OTP_APP "Enable/disable OTP application" ON)
configure_bool_option(
    ENABLE_OTP_APP
    ENABLE_OTP_APP
    "OTP Application: \t\t enabled"
    "OTP Application: \t\t disabled"
)

if(FORBID_DISABLE_AUV)
    add_compile_definitions(FORBID_DISABLE_AUV=1)
endif()
if(DEFAULT_MCUV_NOT_REQUIRED)
    add_compile_definitions(DEFAULT_MCUV_NOT_REQUIRED=1)
endif()
if(DEFAULT_PIN_POLICY)
    add_compile_definitions(DEFAULT_PIN_POLICY=1)
endif()
if(MAX_PIN_RETRIES)
    add_compile_definitions(MAX_PIN_RETRIES=${MAX_PIN_RETRIES})
endif()
if(FORCE_BUTTON_WAIT)
    add_compile_definitions(FORCE_BUTTON_WAIT=1)
endif()

if(ENABLE_OTP_APP OR ENABLE_OATH_APP)
    set(USB_ITF_CCID 1)
    set(USB_ITF_WCID 1)
else()
    set(USB_ITF_CCID 0)
endif()

set(USB_ITF_HID 1)

# ed25519-sk is the preferred SSH algorithm. -DENABLE_EDDSA=OFF opts out.
if(NOT DEFINED ENABLE_EDDSA)
    set(ENABLE_EDDSA ON)
endif()

include(pico-keys-sdk/picokeys_sdk_import.cmake)

set(NKEY_VERSION_FILE "${CMAKE_CURRENT_LIST_DIR}/../VERSION")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${NKEY_VERSION_FILE}")
file(READ "${NKEY_VERSION_FILE}" NKEY_VERSION_TEXT)
string(STRIP "${NKEY_VERSION_TEXT}" NKEY_VERSION_TEXT)
if(NOT NKEY_VERSION_TEXT MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR "VERSION must be major.minor.patch, got '${NKEY_VERSION_TEXT}'")
endif()
set(ver_major_text "${CMAKE_MATCH_1}")
set(ver_minor_text "${CMAKE_MATCH_2}")
set(ver_patch_text "${CMAKE_MATCH_3}")
string(REGEX REPLACE "^0+" "" ver_major_text "${ver_major_text}")
string(REGEX REPLACE "^0+" "" ver_minor_text "${ver_minor_text}")
string(REGEX REPLACE "^0+" "" ver_patch_text "${ver_patch_text}")
if(ver_major_text STREQUAL "")
    set(ver_major_text 0)
endif()
if(ver_minor_text STREQUAL "")
    set(ver_minor_text 0)
endif()
if(ver_patch_text STREQUAL "")
    set(ver_patch_text 0)
endif()
math(EXPR ver_major "${ver_major_text}")
math(EXPR ver_minor "${ver_minor_text}")
math(EXPR ver_patch "${ver_patch_text}")
if(ver_major GREATER 255 OR ver_minor GREATER 255 OR ver_patch GREATER 255)
    message(FATAL_ERROR "VERSION components must be 0..255, got '${NKEY_VERSION_TEXT}'")
endif()
message(STATUS "nkey version:\t\t ${ver_major}.${ver_minor}.${ver_patch}")

if(NOT ESP_PLATFORM)
    set(SOURCES ${PICOKEYS_SOURCES})
endif()

list(APPEND SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/fido.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_authorization.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/resident_container.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/files.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_register.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_authenticate.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_version.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_reset.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_get_info.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_make_credential.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/event.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/known_apps.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_client_pin.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/credential.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_get_assertion.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_selection.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_cred_mgmt.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_config.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_vendor.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/fido_vault.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_large_blobs.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/management.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/maintenance.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/passwd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/passwd_store.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/index.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/index_store.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/defs.c
)

if(ENABLE_OATH_APP)
    list(APPEND SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath.c
    )
endif()

if(ENABLE_OTP_APP)
    list(APPEND SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp.c
    )
endif()

if(PICO_PLATFORM)
    if(NOT PICO_RP2350)
        message(FATAL_ERROR "nkey firmware currently builds for RP2350 only")
    endif()
    if(PICO_RP2350 AND SECURE_BOOT_PKEY)
        message(STATUS "Setting rollback version:\t 5")
        pico_set_binary_version(
            pico_fido
            MAJOR ${ver_major}
            MINOR ${ver_minor}
            ROLLBACK 5
        )
    else()
        pico_set_binary_version(
            pico_fido
            MAJOR ${ver_major}
            MINOR ${ver_minor}
        )
    endif()
endif()
if(ESP_PLATFORM)
    project(pico_fido)
endif()

set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/src/fido
)

if(NOT ESP_PLATFORM)
    target_sources(pico_fido PUBLIC ${SOURCES})
    target_include_directories(pico_fido PUBLIC ${INCLUDES})
    target_compile_definitions(pico_fido PRIVATE
        PICO_FIDO_VERSION_MAJOR=${ver_major}
        PICO_FIDO_VERSION_MINOR=${ver_minor}
        PICO_FIDO_VERSION_PATCH=${ver_patch}
    )

    set(NKEY_BUILD_PATCH_H "${CMAKE_CURRENT_BINARY_DIR}/nkey_build_patch.h")
    add_custom_target(nkey_build_patch
        COMMAND ${CMAKE_COMMAND} -DOUT=${NKEY_BUILD_PATCH_H} -P ${CMAKE_CURRENT_LIST_DIR}/cmake/write_build_patch.cmake
        BYPRODUCTS "${NKEY_BUILD_PATCH_H}"
        COMMENT "Build patch"
        VERBATIM
    )
    add_dependencies(pico_fido nkey_build_patch)
    set_source_files_properties("${NKEY_BUILD_PATCH_H}" PROPERTIES
        GENERATED TRUE
        HEADER_FILE_ONLY TRUE
    )
    target_sources(pico_fido PRIVATE "${NKEY_BUILD_PATCH_H}")
    set_source_files_properties(
        "${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/rescue.c"
        PROPERTIES OBJECT_DEPENDS "${NKEY_BUILD_PATCH_H}"
    )
    target_include_directories(pico_fido PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
    add_custom_command(TARGET pico_fido POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DHEADER=${NKEY_BUILD_PATCH_H} -P ${CMAKE_CURRENT_LIST_DIR}/cmake/print_build_patch.cmake
        VERBATIM
    )

    set(COMMON_COMPILE_OPTIONS
        -Wall
    )
    target_compile_options(pico_fido PRIVATE ${COMMON_COMPILE_OPTIONS})

    picokeys_apply_strict_flags(
        SOURCES ${SOURCES}
        FILTER_REGEX "/src/fido/|/pico-keys-sdk/src/|/pico-keys-sdk/config/"
    )

    if(NOT MSVC)
        string(FIND ${CMAKE_C_COMPILER} ":" COMPILER_COLON)
        if(${COMPILER_COLON} GREATER_EQUAL 0)
            target_compile_options(pico_fido PRIVATE
                -Wno-error=use-after-free
            )
        endif()
    endif()

    if(ENABLE_EMULATION)
        enable_testing()
        if(NOT MSVC)
            set(EMULATION_NON_MSVC_COMPILE_OPTIONS
                -fdata-sections
                -ffunction-sections
            )
            target_compile_options(pico_fido PRIVATE ${EMULATION_NON_MSVC_COMPILE_OPTIONS})
        endif()

        if(APPLE)
            set(EMULATION_APPLE_LINK_OPTIONS
                -Wl,-dead_strip
            )
            target_link_options(pico_fido PRIVATE ${EMULATION_APPLE_LINK_OPTIONS})

            if(DEBUG_APDU)
                set(DEBUG_APDU_SANITIZER_OPTIONS
                    -fsanitize=address
                    -g
                    -O1
                    -fno-omit-frame-pointer
                )
                target_compile_options(pico_fido PRIVATE ${DEBUG_APDU_SANITIZER_OPTIONS})
                target_link_options(pico_fido PRIVATE ${DEBUG_APDU_SANITIZER_OPTIONS})
            endif()
        elseif(NOT MSVC)
            set(EMULATION_NON_APPLE_LINK_OPTIONS
                -Wl,--gc-sections
            )
            target_link_options(pico_fido PRIVATE ${EMULATION_NON_APPLE_LINK_OPTIONS})
        endif()

        target_link_libraries(pico_fido PRIVATE picokeys_sdk mbedtls)
        if(NOT MSVC)
            target_link_libraries(pico_fido PRIVATE pthread m)
        endif()

        add_executable(fido_object_provider_test
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_crypto_provider.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
            ${CMAKE_CURRENT_LIST_DIR}/tests/fido_object_provider_test.c
        )
        target_include_directories(fido_object_provider_test PRIVATE ${INCLUDES})
        if(MSVC)
            target_compile_options(fido_object_provider_test PRIVATE /W4 /WX)
        else()
            target_compile_options(fido_object_provider_test PRIVATE -Wall -Wextra -Werror)
        endif()
        target_link_libraries(fido_object_provider_test PRIVATE mbedtls)
        add_test(NAME fido_object_provider_test COMMAND fido_object_provider_test)

        add_executable(fido_object_authorization_test
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_authorization.c
            ${CMAKE_CURRENT_LIST_DIR}/tests/fido_object_authorization_test.c
        )
        target_include_directories(fido_object_authorization_test PRIVATE ${INCLUDES})
        if(MSVC)
            target_compile_options(fido_object_authorization_test PRIVATE /W4 /WX)
        else()
            target_compile_options(fido_object_authorization_test PRIVATE -Wall -Wextra -Werror)
        endif()
        target_link_libraries(fido_object_authorization_test PRIVATE mbedtls)
        add_test(NAME fido_object_authorization_test COMMAND fido_object_authorization_test)

        add_executable(fido_resident_container_test
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_container.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_container_store.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_crypto_provider.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_policy.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_store_txn.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/resident_container.c
            ${CMAKE_CURRENT_LIST_DIR}/tests/fido_resident_container_test.c
        )
        target_include_directories(fido_resident_container_test PRIVATE ${INCLUDES})
        if(MSVC)
            target_compile_options(fido_resident_container_test PRIVATE /W4 /WX)
        else()
            target_compile_options(fido_resident_container_test PRIVATE -Wall -Wextra -Werror)
        endif()
        target_link_libraries(fido_resident_container_test PRIVATE mbedtls)
        add_test(NAME fido_resident_container_test COMMAND fido_resident_container_test)

        add_executable(fido_oath_container_test
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_container.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_container_store.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_crypto_provider.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_policy.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_store_txn.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath_container.c
            ${CMAKE_CURRENT_LIST_DIR}/tests/fido_oath_container_test.c
        )
        target_include_directories(fido_oath_container_test PRIVATE ${INCLUDES})
        if(MSVC)
            target_compile_options(fido_oath_container_test PRIVATE /W4 /WX)
        else()
            target_compile_options(fido_oath_container_test PRIVATE -Wall -Wextra -Werror)
        endif()
        target_link_libraries(fido_oath_container_test PRIVATE mbedtls)
        add_test(NAME fido_oath_container_test COMMAND fido_oath_container_test)

        add_executable(fido_otp_container_test
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_container.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_container_store.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_crypto_provider.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_policy.c
            ${CMAKE_CURRENT_LIST_DIR}/pico-keys-sdk/src/fs/object_store_txn.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp_container.c
            ${CMAKE_CURRENT_LIST_DIR}/tests/fido_otp_container_test.c
        )
        target_include_directories(fido_otp_container_test PRIVATE ${INCLUDES})
        if(MSVC)
            target_compile_options(fido_otp_container_test PRIVATE /W4 /WX)
        else()
            target_compile_options(fido_otp_container_test PRIVATE -Wall -Wextra -Werror)
        endif()
        target_link_libraries(fido_otp_container_test PRIVATE mbedtls)
        add_test(NAME fido_otp_container_test COMMAND fido_otp_container_test)
    else()
        target_link_libraries(
            pico_fido
            PRIVATE
                picokeys_sdk
                pico_stdlib
                pico_multicore
                hardware_flash
                hardware_sync
                hardware_adc
                pico_unique_id
                pico_aon_timer
                tinyusb_device
                tinyusb_board
        )
        pico_add_extra_outputs(${CMAKE_PROJECT_NAME})
        add_custom_command(TARGET pico_fido POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                -DBINDIR=${CMAKE_CURRENT_BINARY_DIR}
                -DMAJOR=${ver_major}
                -DMINOR=${ver_minor}
                -DPATCH=${ver_patch}
                -DTARGET_NAME=pico_fido
                -P ${CMAKE_CURRENT_LIST_DIR}/cmake/rename_firmware.cmake
            VERBATIM
        )
    endif()
endif()
