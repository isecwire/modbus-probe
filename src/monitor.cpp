#include "monitor.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace modbus_probe {

RegisterMonitor::RegisterMonitor(const MonitorConfig& config)
    : config_(config), ui_(config.color, false) {}

RegisterMonitor::~RegisterMonitor() {
    disconnect();
}

bool RegisterMonitor::connect() {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(config_.port);
    int err = getaddrinfo(config_.host.c_str(), port_str.c_str(), &hints, &res);
    if (err != 0 || !res) return false;

    sock_fd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock_fd_ < 0) {
        freeaddrinfo(res);
        return false;
    }

    // Set receive timeout
    struct timeval tv;
    tv.tv_sec  = config_.timeout_ms / 1000;
    tv.tv_usec = (config_.timeout_ms % 1000) * 1000;
    setsockopt(sock_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(sock_fd_, res->ai_addr, res->ai_addrlen) < 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        freeaddrinfo(res);
        return false;
    }

    freeaddrinfo(res);
    return true;
}

void RegisterMonitor::disconnect() {
    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }
}

std::vector<uint8_t> RegisterMonitor::send_read_request(uint8_t fc,
                                                          uint16_t start,
                                                          uint16_t count) {
    // Build MBAP + PDU
    uint16_t tid = ++transaction_counter_;
    uint16_t length = 6;  // unit_id(1) + fc(1) + addr(2) + qty(2)

    std::vector<uint8_t> request(12);
    request[0]  = static_cast<uint8_t>(tid >> 8);
    request[1]  = static_cast<uint8_t>(tid & 0xFF);
    request[2]  = 0x00;  // protocol ID high
    request[3]  = 0x00;  // protocol ID low
    request[4]  = static_cast<uint8_t>(length >> 8);
    request[5]  = static_cast<uint8_t>(length & 0xFF);
    request[6]  = config_.unit_id;
    request[7]  = fc;
    request[8]  = static_cast<uint8_t>(start >> 8);
    request[9]  = static_cast<uint8_t>(start & 0xFF);
    request[10] = static_cast<uint8_t>(count >> 8);
    request[11] = static_cast<uint8_t>(count & 0xFF);

    // Send
    ssize_t sent = send(sock_fd_, request.data(), request.size(), 0);
    if (sent != static_cast<ssize_t>(request.size())) return {};

    // Receive response (MBAP header first, then PDU)
    std::vector<uint8_t> response(260);
    ssize_t received = recv(sock_fd_, response.data(), response.size(), 0);
    if (received < 9) return {};  // minimum valid response

    response.resize(static_cast<size_t>(received));
    return response;
}

std::map<uint16_t, uint16_t> RegisterMonitor::read_registers() {
    std::map<uint16_t, uint16_t> result;

    auto response = send_read_request(0x03, config_.register_start,
                                       config_.register_count);
    if (response.size() < 9) return result;

    // Check for exception
    if (response[7] & 0x80) return result;

    uint8_t byte_count = response[8];
    size_t expected = 9 + byte_count;
    if (response.size() < expected) return result;

    uint16_t reg_count = byte_count / 2;
    for (uint16_t i = 0; i < reg_count; ++i) {
        size_t offset = 9 + i * 2;
        uint16_t value = (static_cast<uint16_t>(response[offset]) << 8) |
                          response[offset + 1];
        result[config_.register_start + i] = value;
    }

    return result;
}

std::map<uint16_t, bool> RegisterMonitor::read_coils() {
    std::map<uint16_t, bool> result;

    auto response = send_read_request(0x01, config_.coil_start, config_.coil_count);
    if (response.size() < 9) return result;
    if (response[7] & 0x80) return result;

    uint8_t byte_count = response[8];
    size_t expected = 9 + byte_count;
    if (response.size() < expected) return result;

    for (uint16_t i = 0; i < config_.coil_count; ++i) {
        size_t byte_idx = i / 8;
        uint8_t bit_idx = i % 8;
        if (9 + byte_idx < response.size()) {
            bool val = (response[9 + byte_idx] >> bit_idx) & 0x01;
            result[config_.coil_start + i] = val;
        }
    }

    return result;
}

void RegisterMonitor::diff_registers(const std::map<uint16_t, uint16_t>& prev,
                                      const std::map<uint16_t, uint16_t>& curr) {
    for (const auto& [addr, new_val] : curr) {
        auto it = prev.find(addr);
        if (it != prev.end() && it->second != new_val) {
            RegisterChange change;
            change.unit_id   = config_.unit_id;
            change.address   = addr;
            change.old_value = it->second;
            change.new_value = new_val;
            change.timestamp = current_timestamp();
            changes_.push_back(change);
            print_change(change);
            if (config_.on_change) {
                config_.on_change(change);
            }
        }
    }
}

void RegisterMonitor::diff_coils(const std::map<uint16_t, bool>& prev,
                                  const std::map<uint16_t, bool>& curr) {
    for (const auto& [addr, new_val] : curr) {
        auto it = prev.find(addr);
        if (it != prev.end() && it->second != new_val) {
            RegisterChange change;
            change.unit_id   = config_.unit_id;
            change.address   = addr;
            change.old_value = it->second ? 1 : 0;
            change.new_value = new_val ? 1 : 0;
            change.timestamp = current_timestamp();
            changes_.push_back(change);
            print_change(change);
            if (config_.on_change) {
                config_.on_change(change);
            }
        }
    }
}

void RegisterMonitor::print_change(const RegisterChange& change) const {
    const char* red   = config_.color ? ansi::RED   : "";
    const char* green = config_.color ? ansi::GREEN : "";
    const char* cyan  = config_.color ? ansi::CYAN  : "";
    const char* dim   = config_.color ? ansi::DIM   : "";
    const char* reset = config_.color ? ansi::RESET : "";

    std::ostringstream os;
    os << dim << change.timestamp << reset << " "
       << cyan << "unit=" << static_cast<int>(change.unit_id) << reset << " "
       << "reg=" << change.address << " "
       << red << "0x" << std::hex << std::setw(4) << std::setfill('0')
       << change.old_value << reset
       << " -> "
       << green << "0x" << std::hex << std::setw(4) << std::setfill('0')
       << change.new_value << reset
       << " (" << std::dec
       << red << change.old_value << reset
       << " -> "
       << green << change.new_value << reset
       << ")";

    std::cerr << os.str() << "\n";
}

int RegisterMonitor::run() {
    if (!connect()) {
        std::cerr << "Error: Failed to connect to " << config_.host
                  << ":" << config_.port << "\n";
        return -1;
    }

    running_ = true;

    if (!config_.color) {
        std::cerr << "Monitoring registers on " << config_.host << ":"
                  << config_.port << " unit=" << static_cast<int>(config_.unit_id)
                  << " interval=" << config_.interval_ms << "ms\n";
    } else {
        std::cerr << ansi::BOLD << "Monitor mode" << ansi::RESET << " -- "
                  << config_.host << ":" << config_.port
                  << " unit=" << static_cast<int>(config_.unit_id)
                  << " interval=" << config_.interval_ms << "ms"
                  << " (Ctrl+C to stop)\n";
    }

    // Initial read
    auto prev_regs = read_registers();
    std::map<uint16_t, bool> prev_coils;
    if (config_.monitor_coils) {
        prev_coils = read_coils();
    }

    if (prev_regs.empty()) {
        std::cerr << "Warning: Initial register read returned no data\n";
    }

    int iteration = 0;
    while (running_) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.interval_ms));

        if (!running_) break;

        auto curr_regs = read_registers();
        if (!curr_regs.empty()) {
            diff_registers(prev_regs, curr_regs);
            prev_regs = std::move(curr_regs);
        }

        if (config_.monitor_coils) {
            auto curr_coils = read_coils();
            if (!curr_coils.empty()) {
                diff_coils(prev_coils, curr_coils);
                prev_coils = std::move(curr_coils);
            }
        }

        ++iteration;
        if (config_.max_iterations > 0 && iteration >= config_.max_iterations) {
            break;
        }
    }

    disconnect();
    return static_cast<int>(changes_.size());
}

void RegisterMonitor::stop() {
    running_ = false;
}

std::string RegisterMonitor::current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm tm_buf{};
    gmtime_r(&time_t, &tm_buf);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    std::ostringstream os;
    os << buf << "." << std::setw(3) << std::setfill('0') << ms.count() << "Z";
    return os.str();
}

}  // namespace modbus_probe
