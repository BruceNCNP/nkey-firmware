if(NOT DEFINED BINDIR OR NOT DEFINED MAJOR OR NOT DEFINED MINOR OR NOT DEFINED PATCH OR NOT DEFINED TARGET_NAME)
    message(FATAL_ERROR "BINDIR, MAJOR, MINOR, PATCH and TARGET_NAME are required")
endif()

set(base "nkey-rp2350-${MAJOR}.${MINOR}.${PATCH}")

file(GLOB stale "${BINDIR}/nkey-rp2350-*")
foreach(path ${stale})
    file(REMOVE "${path}")
endforeach()

set(suffixes .elf .elf.map .bin .hex .uf2 .dis)
foreach(suffix ${suffixes})
    set(src "${BINDIR}/${TARGET_NAME}${suffix}")
    if(NOT EXISTS "${src}")
        message(FATAL_ERROR "Missing firmware output ${src}")
    endif()
    file(RENAME "${src}" "${BINDIR}/${base}${suffix}")
endforeach()

message(STATUS "Firmware: ${base}")
