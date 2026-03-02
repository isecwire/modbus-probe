#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modbus_probe {

// Forward declarations for types used in report
struct FuzzEntry;
struct DeviceIdentification;

// Severity classification for findings
enum class FindingSeverity {
    INFO,       // Device responsive
    MEDIUM,     // Device information leak (e.g., Device ID)
    HIGH,       // Unauthenticated read access
    CRITICAL,   // Unauthenticated write access
};

std::string severity_to_string(FindingSeverity sev);

struct RegisterData {
    uint16_t address;
    uint16_t value;
};

struct Finding {
    FindingSeverity severity;
    std::string category;     // e.g. "unauthorized_write", "unauthorized_read"
    std::string description;
};

struct UnitResult {
    uint8_t unit_id;
    bool responsive;
    bool holding_registers_readable;
    bool input_registers_readable;
    bool coils_readable;
    bool write_test_performed;
    bool write_test_vulnerable;  // true = unauthorized write succeeded
    std::string write_test_detail;
    std::vector<RegisterData> holding_registers;
    std::vector<RegisterData> input_registers;
    std::vector<std::pair<uint16_t, bool>> coils;
    std::string error;

    // Device identification (FC43/14)
    bool device_id_supported = false;
    std::string device_vendor;
    std::string device_product_code;
    std::string device_revision;
    std::string device_vendor_url;
    std::string device_product_name;
    std::string device_model_name;

    // Response timing analysis
    std::vector<double> timing_samples;  // per-operation latencies in ms

    // Function code fuzz results (populated only in fuzz mode)
    std::vector<uint8_t> supported_function_codes;

    // Aggregated findings
    std::vector<Finding> findings;
};

struct ScanReport {
    std::string target_host;
    uint16_t target_port;
    std::string scan_start;
    std::string scan_end;
    std::string tool_version;
    std::string protocol_mode;   // "tcp" or "rtu_over_tcp"
    uint32_t units_scanned;
    uint32_t units_responsive;
    uint32_t unauthenticated_reads;
    uint32_t unauthenticated_writes;
    uint32_t devices_identified;  // units that responded to FC43/14
    uint32_t thread_count;
    std::vector<UnitResult> results;
};

class ReportGenerator {
public:
    static std::string to_json(const ScanReport& report);
    static bool write_file(const std::string& path, const ScanReport& report);

private:
    static std::string escape_json(const std::string& s);
    static std::string indent(int level);
};

}  // namespace modbus_probe
