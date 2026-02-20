#pragma once
// ---------------------------------------------------------------------------
// fuzzer.h -- Modbus function code fuzzer
//
// Sends every function code (1-127) to a target unit ID and records which
// codes produce valid responses vs exceptions vs timeouts.  Useful for
// discovering undocumented or vendor-specific function codes.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <vector>

namespace modbus_probe {

enum class FuzzResultType : uint8_t {
    Supported,       // Valid response (no exception)
    Exception,       // Exception response received
    Timeout,         // No response within timeout
    Error,           // Communication error
};

struct FuzzEntry {
    uint8_t function_code;
    FuzzResultType result_type;
    uint8_t exception_code;      // only valid if result_type == Exception
    double response_time_ms;     // round-trip time
    std::string description;     // human-readable FC name + result
};

struct FuzzReport {
    uint8_t unit_id;
    uint32_t total_tested;
    uint32_t supported_count;
    uint32_t exception_count;
    uint32_t timeout_count;
    uint32_t error_count;
    std::vector<FuzzEntry> entries;
};

class FunctionCodeFuzzer {
public:
    // Return a human-readable name for standard Modbus function codes
    static std::string fc_name(uint8_t fc);

    // Return a human-readable name for exception codes
    static std::string exception_name(uint8_t ec);

    // Classify a FuzzResultType as a severity string
    static std::string result_type_str(FuzzResultType rt);
};

}  // namespace modbus_probe
