#include "discovery.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace modbus_probe {

NetworkDiscovery::NetworkDiscovery(const DiscoveryConfig& config)
    : config_(config), ui_(config.color, config.quiet) {}

// ---------------------------------------------------------------------------
// CIDR expansion
// ---------------------------------------------------------------------------

uint32_t NetworkDiscovery::parse_ipv4(const std::string& ip) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return 0;
    return ntohl(addr.s_addr);
}

std::string NetworkDiscovery::ipv4_to_string(uint32_t ip) {
    struct in_addr addr{};
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

std::vector<std::string> NetworkDiscovery::expand_cidr(const std::string& cidr) {
    std::vector<std::string> ips;

    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        // Single IP
        ips.push_back(cidr);
        return ips;
    }

    std::string base_ip = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));

    if (prefix_len < 0 || prefix_len > 32) return ips;

    uint32_t base = parse_ipv4(base_ip);
    uint32_t mask = (prefix_len == 0) ? 0 : (~0U << (32 - prefix_len));
    uint32_t network = base & mask;
    uint32_t broadcast = network | ~mask;

    // For /31 and /32, include all addresses
    if (prefix_len >= 31) {
        for (uint32_t addr = network; addr <= broadcast; ++addr) {
            ips.push_back(ipv4_to_string(addr));
        }
    } else {
        // Skip network and broadcast addresses
        for (uint32_t addr = network + 1; addr < broadcast; ++addr) {
            ips.push_back(ipv4_to_string(addr));
        }
    }

    return ips;
}

// ---------------------------------------------------------------------------
// Single host probe
// ---------------------------------------------------------------------------

DiscoveredHost NetworkDiscovery::probe_host(const std::string& ip) {
    DiscoveredHost host;
    host.ip = ip;
    host.port = config_.port;
    host.modbus_responsive = false;
    host.latency_ms = -1;

    // Create non-blocking socket
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return host;

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    auto start = std::chrono::steady_clock::now();

    int ret = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        ::close(fd);
        return host;
    }

    // Wait for connect with timeout
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;

    ret = poll(&pfd, 1, config_.timeout_ms);
    if (ret <= 0 || !(pfd.revents & POLLOUT)) {
        ::close(fd);
        return host;
    }

    // Check for connect error
    int sock_err = 0;
    socklen_t err_len = sizeof(sock_err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
    if (sock_err != 0) {
        ::close(fd);
        return host;
    }

    auto end = std::chrono::steady_clock::now();
    host.latency_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

    // Restore blocking mode for Modbus probing
    fcntl(fd, F_SETFL, flags);

    // Set receive timeout
    struct timeval tv;
    tv.tv_sec  = config_.timeout_ms / 1000;
    tv.tv_usec = (config_.timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (config_.probe_modbus) {
        host.modbus_responsive = probe_modbus_fc03(fd);
    }

    if (host.modbus_responsive && config_.read_device_id) {
        probe_device_id(fd, host.device_vendor, host.device_product);
    }

    ::close(fd);
    return host;
}

bool NetworkDiscovery::probe_modbus_fc03(int fd) {
    // Build a minimal FC03 request: read 1 register at address 0, unit ID 1
    // MBAP header (7 bytes) + PDU (5 bytes) = 12 bytes
    uint8_t request[] = {
        0x00, 0x01,  // Transaction ID
        0x00, 0x00,  // Protocol ID (Modbus)
        0x00, 0x06,  // Length (6 bytes follow)
        0x01,        // Unit ID
        0x03,        // FC03: Read Holding Registers
        0x00, 0x00,  // Start address
        0x00, 0x01,  // Quantity (1 register)
    };

    ssize_t sent = send(fd, request, sizeof(request), 0);
    if (sent != sizeof(request)) return false;

    uint8_t response[260];
    ssize_t received = recv(fd, response, sizeof(response), 0);

    // Any response (even an exception) means Modbus is running
    return received >= 9;
}

bool NetworkDiscovery::probe_device_id(int fd, std::string& vendor,
                                        std::string& product) {
    // FC43/14: Read Device Identification, basic stream (code=1), object 0
    uint8_t request[] = {
        0x00, 0x02,  // Transaction ID
        0x00, 0x00,  // Protocol ID
        0x00, 0x05,  // Length
        0x01,        // Unit ID
        0x2B,        // FC43
        0x0E,        // MEI type: Read Device Identification
        0x01,        // Read Device ID code: basic
        0x00,        // Object ID: vendor name
    };

    ssize_t sent = send(fd, request, sizeof(request), 0);
    if (sent != sizeof(request)) return false;

    uint8_t response[260];
    ssize_t received = recv(fd, response, sizeof(response), 0);
    if (received < 15) return false;

    // Check for valid FC43 response (not exception)
    if (response[7] == 0xAB) return false;  // exception
    if (response[7] != 0x2B) return false;

    // Parse objects: offset 13 = number of objects
    size_t offset = 14;  // first object
    int num_objects = response[13];

    for (int i = 0; i < num_objects && offset + 2 < static_cast<size_t>(received); ++i) {
        uint8_t obj_id = response[offset];
        uint8_t obj_len = response[offset + 1];
        offset += 2;

        if (offset + obj_len > static_cast<size_t>(received)) break;

        std::string value(reinterpret_cast<const char*>(&response[offset]), obj_len);
        offset += obj_len;

        switch (obj_id) {
            case 0x00: vendor  = value; break;
            case 0x01: product = value; break;
            default: break;
        }
    }

    return !vendor.empty();
}
