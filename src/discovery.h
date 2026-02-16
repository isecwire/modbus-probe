#pragma once
// ---------------------------------------------------------------------------
// discovery.h -- Network discovery for Modbus devices
//
// Scans an IP range (CIDR notation) for hosts with open TCP port 502
// (or a custom port). Reports responsive hosts with optional Modbus
// unit ID probing.
// ---------------------------------------------------------------------------

#include "progress.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace modbus_probe {

// Result for a single discovered host
struct DiscoveredHost {
    std::string ip;
    uint16_t    port;
    bool        modbus_responsive;  // responded to FC03 probe
    int         latency_ms;         // TCP connect latency
    std::string device_vendor;      // from FC43/14 if available
    std::string device_product;
};

// Configuration for network discovery
struct DiscoveryConfig {
    std::string cidr;               // e.g. "192.168.1.0/24"
    uint16_t    port         = 502;
    int         timeout_ms   = 500; // per-host connect timeout
    int         thread_count = 16;
    bool        probe_modbus = true;  // send FC03 after connect
    bool        read_device_id = false; // attempt FC43/14
    bool        color        = true;
    bool        quiet        = false;
};

class NetworkDiscovery {
public:
    explicit NetworkDiscovery(const DiscoveryConfig& config);
    ~NetworkDiscovery() = default;

    NetworkDiscovery(const NetworkDiscovery&) = delete;
    NetworkDiscovery& operator=(const NetworkDiscovery&) = delete;

    // Run discovery scan; returns number of responsive hosts
    int run();

    // Stop the scan
    void stop();

    // Get results after run() completes
    const std::vector<DiscoveredHost>& results() const { return results_; }

    // Format results as a summary string (table)
    std::string format_results() const;

    // Format results as JSON
    std::string format_json() const;

protected:
    // Parse CIDR into list of IPs
    static std::vector<std::string> expand_cidr(const std::string& cidr);

    // Parse an IPv4 address string to a 32-bit integer
    static uint32_t parse_ipv4(const std::string& ip);

    // Convert a 32-bit integer to an IPv4 string
    static std::string ipv4_to_string(uint32_t ip);

private:

    // Probe a single host: TCP connect + optional Modbus FC03
    DiscoveredHost probe_host(const std::string& ip);

    // Attempt a Modbus FC03 read on an established socket
    bool probe_modbus_fc03(int fd);

    // Attempt FC43/14 device identification on an established socket
    bool probe_device_id(int fd, std::string& vendor, std::string& product);

    // Worker thread function
    void worker(const std::vector<std::string>& ips, size_t start, size_t end);

    DiscoveryConfig config_;
    std::vector<DiscoveredHost> results_;
    std::mutex results_mutex_;
    std::atomic<bool> running_{false};
    std::atomic<uint32_t> progress_{0};
    uint32_t total_hosts_ = 0;
    TerminalUI ui_;
};

}  // namespace modbus_probe
