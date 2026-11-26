if(NOT DEFINED HEADER)
    message(FATAL_ERROR "HEADER is required")
endif()

file(STRINGS "${HEADER}" line REGEX "#define NKEY_BUILD_PATCH ")
string(REGEX REPLACE ".*NKEY_BUILD_PATCH ([0-9]+).*" "\\1" patch "${line}")
message(STATUS "Build patch: ${patch}")
