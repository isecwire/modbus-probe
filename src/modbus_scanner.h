#pragma once

#include "device_id.h"
#include "fuzzer.h"
#include "progress.h"
#include "report.h"
#include "rtu_framing.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace modbus_probe {

// Modbus function codes
enum class FunctionCode : uint8_t {
    ReadCoils              = 0x01,
    ReadDiscreteInputs     = 0x02,
    ReadHoldingRegisters   = 0x03,
    ReadInputRegisters     = 0x04,
    WriteSingleCoil        = 0x05,
    WriteSingleRegister    = 0x06,
    WriteMultipleCoils     = 0x0F,
    WriteMultipleRegisters = 0x10,
    ReadDeviceId           = 0x2B,  // FC43 / MEI
};

// Modbus exception codes
enum class ExceptionCode : uint8_t {
    IllegalFunction    = 0x01,
    IllegalDataAddress = 0x02,
    IllegalDataValue   = 0x03,
    SlaveDeviceFailure = 0x04,
    Acknowledge        = 0x05,
    SlaveDeviceBusy    = 0x06,
    GatewayPathUnavail = 0x0A,
    GatewayTargetFail  = 0x0B,
};

// MBAP header (Modbus Application Protocol header for TCP)
struct MBAPHeader {
    uint16_t transaction_id;
    uint16_t protocol_id;   // always 0x0000 for Modbus
    uint16_t length;        // bytes following (unit_id + PDU)
    uint8_t  unit_id;
};

// Protocol framing mode
enum class ProtocolMode {
    TCP,            // Standard Modbus TCP (MBAP header)
    RTU_OVER_TCP,   // RTU framing tunnelled over TCP (CRC16, no MBAP)
};

// Register range specification (supports multiple comma-separated ranges)
struct RegisterRange {
    uint16_t start;
    uint16_t count;
};

struct ScanConfig {
    std::string host;
    uint16_t port = 502;
    uint8_t id_start = 1;
    uint8_t id_end = 247;
    bool test_write = false;
    uint16_t register_start = 0;
    uint16_t register_count = 10;
    uint16_t coil_start = 0;
    uint16_t coil_count = 16;
    int timeout_ms = 2000;
    int connect_timeout_ms = 3000;

    // New v2 options
    ProtocolMode protocol_mode = ProtocolMode::TCP;
    int thread_count = 1;
    bool fuzz_function_codes = false;
    uint8_t fuzz_unit_id = 1;          // unit ID to fuzz (when --fuzz used)
    bool read_device_id = true;        // attempt FC43/14 on responsive units
    bool verbose = false;
    bool quiet = false;
    bool color = true;
    std::string output_format = "json";  // json, csv, table
    std::vector<RegisterRange> extra_ranges;  // from --range
};

// Parse a range string like "0-100,400-500" into RegisterRange vector
std::vector<RegisterRange> parse_register_ranges(const std::string& s);

class ModbusScanner {
public:
    explicit ModbusScanner(const ScanConfig& config);
    ~ModbusScanner();

    ModbusScanner(const ModbusScanner&) = delete;
    ModbusScanner& operator=(const ModbusScanner&) = delete;

    // Run full scan, returns completed report
    ScanReport run();

    // Run function code fuzz against a single unit ID
    FuzzReport run_fuzz(uint8_t unit_id);

    // Set verbose callback for progress output
    using LogCallback = std::function<void(const std::string&)>;
    void set_log_callback(LogCallback cb);

private:
    // TCP connection management
    bool tcp_connect();
    bool tcp_connect(int& fd);   // connect to a new fd (for multi-threading)
    void tcp_disconnect();
    void tcp_disconnect(int& fd);

    // Low-level Modbus TCP frame building and I/O
    std::vector<uint8_t> build_request(uint8_t unit_id, FunctionCode fc,
                                        uint16_t start_addr, uint16_t quantity);
    std::vector<uint8_t> build_write_single_register(uint8_t unit_id,
                                                      uint16_t addr, uint16_t value);
    std::vector<uint8_t> build_write_single_coil(uint8_t unit_id,
                                                  uint16_t addr, bool value);
    std::vector<uint8_t> build_write_multiple_registers(uint8_t unit_id,
                                                         uint16_t start_addr,
                                                         const std::vector<uint16_t>& values);
    std::vector<uint8_t> build_write_multiple_coils(uint8_t unit_id,
                                                     uint16_t start_addr,
                                                     const std::vector<bool>& values);
    std::vector<uint8_t> build_device_id_request(uint8_t unit_id);
    std::vector<uint8_t> build_raw_fc_request(uint8_t unit_id, uint8_t fc,
                                               const std::vector<uint8_t>& payload = {});

    // Network I/O
    std::vector<uint8_t> send_receive(const std::vector<uint8_t>& request);
    std::vector<uint8_t> send_receive(int fd, const std::vector<uint8_t>& request);

    // Timed send/receive (returns round-trip time in ms via out param)
    std::vector<uint8_t> send_receive_timed(const std::vector<uint8_t>& request, double& elapsed_ms);

    // High-level scan operations per unit ID
    UnitResult scan_unit(uint8_t unit_id);
    UnitResult scan_unit_on_fd(int fd, uint8_t unit_id);
    bool read_holding_registers(UnitResult& result);
    bool read_input_registers(UnitResult& result);
    bool read_coils(UnitResult& result);
    bool read_discrete_inputs(UnitResult& result);
    bool test_write_access(UnitResult& result);
    bool read_device_identification(UnitResult& result);
    bool scan_register_range(UnitResult& result, uint16_t start, uint16_t count);

    // Function code fuzzing
    FuzzEntry fuzz_single_fc(int fd, uint8_t unit_id, uint8_t fc);

    // Parse response helpers
    bool is_exception_response(const std::vector<uint8_t>& response) const;
    ExceptionCode get_exception_code(const std::vector<uint8_t>& response) const;
    std::vector<uint16_t> parse_register_response(const std::vector<uint8_t>& response);
    std::vector<bool> parse_coil_response(const std::vector<uint8_t>& response, uint16_t count);
    DeviceIdentification parse_device_id_response(const std::vector<uint8_t>& response);

    // Utilities
    uint16_t next_transaction_id();
    std::string current_timestamp() const;
    void log(const std::string& msg);

    // Classify findings for a unit result
    void classify_findings(UnitResult& result);

    ScanConfig config_;
    int sock_fd_ = -1;
    uint16_t transaction_counter_ = 0;
    LogCallback log_cb_;
    std::mutex log_mutex_;
    std::mutex tid_mutex_;
    std::atomic<uint32_t> progress_current_{0};
    TerminalUI ui_;
};

}  // namespace modbus_probe
