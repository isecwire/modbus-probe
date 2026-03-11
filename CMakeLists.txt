cmake_minimum_required(VERSION 3.14)
project(modbus-probe
    VERSION 2.2.0
    DESCRIPTION "Modbus TCP/RTU security scanner and auditor for OT/SCADA environments"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Core library sources (shared between main binary and tests) ────────────

set(LIB_SOURCES
    src/modbus_scanner.cpp
    src/report.cpp
    src/rtu_framing.cpp
    src/device_id.cpp
    src/fuzzer.cpp
    src/progress.cpp
    src/table_formatter.cpp
    src/pcap_writer.cpp
    src/monitor.cpp
    src/discovery.cpp
)

# ─── Main executable ────────────────────────────────────────────────────────

add_executable(modbus-probe
    src/main.cpp
    ${LIB_SOURCES}
)

target_include_directories(modbus-probe PRIVATE src)

find_package(Threads REQUIRED)
target_link_libraries(modbus-probe PRIVATE Threads::Threads)

target_compile_options(modbus-probe PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Debug>:-g -O0 -fsanitize=address>
)

target_link_options(modbus-probe PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address>
)

install(TARGETS modbus-probe RUNTIME DESTINATION bin)

# ─── Test target ─────────────────────────────────────────────────────────────

enable_testing()

add_executable(modbus-probe-tests
    tests/main_test.cpp
    tests/test_modbus_scanner.cpp
    tests/test_report.cpp
    tests/test_rtu_framing.cpp
    tests/test_device_id.cpp
    tests/test_pcap_writer.cpp
    tests/test_discovery.cpp
    ${LIB_SOURCES}
)

target_include_directories(modbus-probe-tests PRIVATE src tests)
target_link_libraries(modbus-probe-tests PRIVATE Threads::Threads)

target_compile_options(modbus-probe-tests PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Debug>:-g -O0>
)

add_test(NAME modbus-probe-tests COMMAND modbus-probe-tests)
