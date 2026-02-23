#pragma once
// ---------------------------------------------------------------------------
// monitor.h -- Register change monitoring mode
//
// Continuously polls Modbus registers at a configurable interval and detects
// value changes, printing colored diff output to stderr. Useful for
// observing PLC behavior during security testing.
// ---------------------------------------------------------------------------

#include "modbus_scanner.h"
#include "progress.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace modbus_probe {

// A single detected register change
struct RegisterChange {
    uint8_t  unit_id;
    uint16_t address;
    uint16_t old_value;
    uint16_t new_value;
    std::string timestamp;
};

// Configuration for monitor mode
struct MonitorConfig {
    std::string host;
    uint16_t port             = 502;
    uint8_t  unit_id          = 1;
    uint16_t register_start   = 0;
    uint16_t register_count   = 10;
    int      interval_ms      = 1000;   // polling interval
    int      timeout_ms       = 2000;
    int      max_iterations   = 0;      // 0 = infinite
    bool     color            = true;
    bool     monitor_coils    = false;  // also monitor coil states
    uint16_t coil_start       = 0;
    uint16_t coil_count       = 16;

    // Optional callback for each detected change (for programmatic use)
    std::function<void(const RegisterChange&)> on_change;
};

class RegisterMonitor {
public:
    explicit RegisterMonitor(const MonitorConfig& config);
    ~RegisterMonitor();

    RegisterMonitor(const RegisterMonitor&) = delete;
    RegisterMonitor& operator=(const RegisterMonitor&) = delete;

    // Run the monitoring loop (blocks until stopped or max_iterations reached)
    // Returns total number of changes detected
    int run();

    // Stop the monitor (can be called from a signal handler)
    void stop();

    // Get all detected changes
    const std::vector<RegisterChange>& changes() const { return changes_; }

private:
    // Connect to the target
    bool connect();
    void disconnect();

    // Read current register values, returns empty on failure
    std::map<uint16_t, uint16_t> read_registers();

    // Read current coil values
    std::map<uint16_t, bool> read_coils();

    // Compare old vs new and emit changes
    void diff_registers(const std::map<uint16_t, uint16_t>& prev,
                        const std::map<uint16_t, uint16_t>& curr);
    void diff_coils(const std::map<uint16_t, bool>& prev,
                    const std::map<uint16_t, bool>& curr);

    // Print a single change line with color
    void print_change(const RegisterChange& change) const;

    // Build and send a Modbus TCP read request, return response
    std::vector<uint8_t> send_read_request(uint8_t fc, uint16_t start, uint16_t count);

    // Get current ISO 8601 timestamp
    static std::string current_timestamp();

    MonitorConfig config_;
    int sock_fd_ = -1;
    uint16_t transaction_counter_ = 0;
    std::atomic<bool> running_{false};
    std::vector<RegisterChange> changes_;
    TerminalUI ui_;
};

}  // namespace modbus_probe
