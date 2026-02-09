#include "modbus_scanner.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <future>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace modbus_probe {

// ---------------------------------------------------------------------------
// Register range parsing
// ---------------------------------------------------------------------------

std::vector<RegisterRange> parse_register_ranges(const std::string& s) {
    std::vector<RegisterRange> ranges;
    std::istringstream stream(s);
    std::string token;
    while (std::getline(stream, token, ',')) {
        auto dash = token.find('-');
        if (dash == std::string::npos) {
            // Single address
            try {
                uint16_t addr = static_cast<uint16_t>(std::stoul(token));
                ranges.push_back({addr, 1});
            } catch (...) {}
        } else {
            try {
                uint16_t start = static_cast<uint16_t>(std::stoul(token.substr(0, dash)));
                uint16_t end = static_cast<uint16_t>(std::stoul(token.substr(dash + 1)));
                if (end >= start) {
                    ranges.push_back({start, static_cast<uint16_t>(end - start + 1)});
                }
            } catch (...) {}
        }
    }
    return ranges;
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

ModbusScanner::ModbusScanner(const ScanConfig& config)
    : config_(config)
    , ui_(config.color, config.quiet)
{}

ModbusScanner::~ModbusScanner() {
    tcp_disconnect();
}

void ModbusScanner::set_log_callback(LogCallback cb) {
    log_cb_ = std::move(cb);
}

void ModbusScanner::log(const std::string& msg) {
    if (log_cb_) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_cb_(msg);
    }
}

std::string ModbusScanner::current_timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    struct tm tm_buf {};
    gmtime_r(&t, &tm_buf);
    std::ostringstream os;
    os << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return os.str();
}

uint16_t ModbusScanner::next_transaction_id() {
    std::lock_guard<std::mutex> lock(tid_mutex_);
    return ++transaction_counter_;
}

// ---------------------------------------------------------------------------
// TCP connection
// ---------------------------------------------------------------------------

bool ModbusScanner::tcp_connect() {
    tcp_disconnect();

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(config_.port);
    struct addrinfo* res = nullptr;
    int rv = getaddrinfo(config_.host.c_str(), port_str.c_str(), &hints, &res);
    if (rv != 0) {
        log("DNS resolution failed: " + std::string(gai_strerror(rv)));
        return false;
    }

    for (auto* p = res; p != nullptr; p = p->ai_next) {
        sock_fd_ = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock_fd_ < 0) continue;

        int flags = fcntl(sock_fd_, F_GETFL, 0);
        fcntl(sock_fd_, F_SETFL, flags | O_NONBLOCK);

        rv = connect(sock_fd_, p->ai_addr, p->ai_addrlen);
        if (rv < 0 && errno != EINPROGRESS) {
            close(sock_fd_);
            sock_fd_ = -1;
            continue;
        }

        if (rv < 0) {
            struct pollfd pfd {};
            pfd.fd = sock_fd_;
            pfd.events = POLLOUT;
            int poll_rv = poll(&pfd, 1, config_.connect_timeout_ms);
            if (poll_rv <= 0) {
                close(sock_fd_);
                sock_fd_ = -1;
                continue;
            }
            int sock_err = 0;
            socklen_t len = sizeof(sock_err);
            getsockopt(sock_fd_, SOL_SOCKET, SO_ERROR, &sock_err, &len);
            if (sock_err != 0) {
                close(sock_fd_);
                sock_fd_ = -1;
                continue;
            }
        }

        fcntl(sock_fd_, F_SETFL, flags);
        freeaddrinfo(res);
        return true;
    }

    freeaddrinfo(res);
    return false;
}

bool ModbusScanner::tcp_connect(int& fd) {
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(config_.port);
    struct addrinfo* res = nullptr;
    int rv = getaddrinfo(config_.host.c_str(), port_str.c_str(), &hints, &res);
    if (rv != 0) return false;

    for (auto* p = res; p != nullptr; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        rv = connect(fd, p->ai_addr, p->ai_addrlen);
        if (rv < 0 && errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }

        if (rv < 0) {
            struct pollfd pfd {};
            pfd.fd = fd;
            pfd.events = POLLOUT;
            int poll_rv = poll(&pfd, 1, config_.connect_timeout_ms);
            if (poll_rv <= 0) {
                close(fd);
                fd = -1;
                continue;
            }
            int sock_err = 0;
            socklen_t len = sizeof(sock_err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &len);
            if (sock_err != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }

        fcntl(fd, F_SETFL, flags);
        freeaddrinfo(res);
        return true;
    }

    freeaddrinfo(res);
    fd = -1;
    return false;
}

void ModbusScanner::tcp_disconnect() {
    if (sock_fd_ >= 0) {
        close(sock_fd_);
        sock_fd_ = -1;
    }
}

void ModbusScanner::tcp_disconnect(int& fd) {
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

// ---------------------------------------------------------------------------
// Modbus TCP frame building
// ---------------------------------------------------------------------------

std::vector<uint8_t> ModbusScanner::build_request(uint8_t unit_id, FunctionCode fc,
                                                    uint16_t start_addr, uint16_t quantity) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return RtuFraming::build_read_request(unit_id, static_cast<uint8_t>(fc),
                                               start_addr, quantity);
    }

    uint16_t tid = next_transaction_id();
    uint16_t pdu_len = 5;
    uint16_t mbap_length = 1 + pdu_len;

    std::vector<uint8_t> frame(7 + pdu_len);
    frame[0] = static_cast<uint8_t>(tid >> 8);
    frame[1] = static_cast<uint8_t>(tid & 0xFF);
    frame[2] = 0x00;
    frame[3] = 0x00;
    frame[4] = static_cast<uint8_t>(mbap_length >> 8);
    frame[5] = static_cast<uint8_t>(mbap_length & 0xFF);
    frame[6] = unit_id;
    frame[7] = static_cast<uint8_t>(fc);
    frame[8] = static_cast<uint8_t>(start_addr >> 8);
    frame[9] = static_cast<uint8_t>(start_addr & 0xFF);
    frame[10] = static_cast<uint8_t>(quantity >> 8);
    frame[11] = static_cast<uint8_t>(quantity & 0xFF);

    return frame;
}

std::vector<uint8_t> ModbusScanner::build_write_single_register(uint8_t unit_id,
                                                                  uint16_t addr, uint16_t value) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return RtuFraming::build_write_single_register(unit_id, addr, value);
    }

    uint16_t tid = next_transaction_id();
    uint16_t pdu_len = 5;
    uint16_t mbap_length = 1 + pdu_len;

    std::vector<uint8_t> frame(7 + pdu_len);
    frame[0] = static_cast<uint8_t>(tid >> 8);
    frame[1] = static_cast<uint8_t>(tid & 0xFF);
    frame[2] = 0x00;
    frame[3] = 0x00;
    frame[4] = static_cast<uint8_t>(mbap_length >> 8);
    frame[5] = static_cast<uint8_t>(mbap_length & 0xFF);
    frame[6] = unit_id;
    frame[7] = static_cast<uint8_t>(FunctionCode::WriteSingleRegister);
    frame[8] = static_cast<uint8_t>(addr >> 8);
    frame[9] = static_cast<uint8_t>(addr & 0xFF);
    frame[10] = static_cast<uint8_t>(value >> 8);
    frame[11] = static_cast<uint8_t>(value & 0xFF);

    return frame;
}

std::vector<uint8_t> ModbusScanner::build_write_single_coil(uint8_t unit_id,
                                                              uint16_t addr, bool value) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return RtuFraming::build_write_single_coil(unit_id, addr, value);
    }

    uint16_t tid = next_transaction_id();
    uint16_t pdu_len = 5;
    uint16_t mbap_length = 1 + pdu_len;

    std::vector<uint8_t> frame(7 + pdu_len);
    frame[0] = static_cast<uint8_t>(tid >> 8);
    frame[1] = static_cast<uint8_t>(tid & 0xFF);
    frame[2] = 0x00;
    frame[3] = 0x00;
    frame[4] = static_cast<uint8_t>(mbap_length >> 8);
    frame[5] = static_cast<uint8_t>(mbap_length & 0xFF);
    frame[6] = unit_id;
    frame[7] = static_cast<uint8_t>(FunctionCode::WriteSingleCoil);
    frame[8] = static_cast<uint8_t>(addr >> 8);
    frame[9] = static_cast<uint8_t>(addr & 0xFF);
    frame[10] = value ? 0xFF : 0x00;
    frame[11] = 0x00;

    return frame;
}

std::vector<uint8_t> ModbusScanner::build_write_multiple_registers(uint8_t unit_id,
                                                                     uint16_t start_addr,
                                                                     const std::vector<uint16_t>& values) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return RtuFraming::build_write_multiple_registers(unit_id, start_addr, values);
    }

    // FC16: fc(1) + addr(2) + qty(2) + byte_count(1) + data(N*2)
    uint16_t tid = next_transaction_id();
    uint16_t quantity = static_cast<uint16_t>(values.size());
    uint8_t byte_count = static_cast<uint8_t>(quantity * 2);
    uint16_t pdu_len = 6 + byte_count;
    uint16_t mbap_length = 1 + pdu_len;

    std::vector<uint8_t> frame;
    frame.reserve(7 + pdu_len);
    frame.push_back(static_cast<uint8_t>(tid >> 8));
    frame.push_back(static_cast<uint8_t>(tid & 0xFF));
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(static_cast<uint8_t>(mbap_length >> 8));
    frame.push_back(static_cast<uint8_t>(mbap_length & 0xFF));
    frame.push_back(unit_id);
    frame.push_back(static_cast<uint8_t>(FunctionCode::WriteMultipleRegisters));
    frame.push_back(static_cast<uint8_t>(start_addr >> 8));
    frame.push_back(static_cast<uint8_t>(start_addr & 0xFF));
    frame.push_back(static_cast<uint8_t>(quantity >> 8));
    frame.push_back(static_cast<uint8_t>(quantity & 0xFF));
    frame.push_back(byte_count);
    for (auto val : values) {
        frame.push_back(static_cast<uint8_t>(val >> 8));
        frame.push_back(static_cast<uint8_t>(val & 0xFF));
    }

    return frame;
}

std::vector<uint8_t> ModbusScanner::build_write_multiple_coils(uint8_t unit_id,
                                                                 uint16_t start_addr,
                                                                 const std::vector<bool>& values) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return RtuFraming::build_write_multiple_coils(unit_id, start_addr, values);
    }

    uint16_t tid = next_transaction_id();
    uint16_t quantity = static_cast<uint16_t>(values.size());
    uint8_t byte_count = static_cast<uint8_t>((quantity + 7) / 8);
    uint16_t pdu_len = 6 + byte_count;
    uint16_t mbap_length = 1 + pdu_len;

    std::vector<uint8_t> frame;
    frame.reserve(7 + pdu_len);
    frame.push_back(static_cast<uint8_t>(tid >> 8));
    frame.push_back(static_cast<uint8_t>(tid & 0xFF));
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(static_cast<uint8_t>(mbap_length >> 8));
    frame.push_back(static_cast<uint8_t>(mbap_length & 0xFF));
    frame.push_back(unit_id);
    frame.push_back(static_cast<uint8_t>(FunctionCode::WriteMultipleCoils));
    frame.push_back(static_cast<uint8_t>(start_addr >> 8));
    frame.push_back(static_cast<uint8_t>(start_addr & 0xFF));
    frame.push_back(static_cast<uint8_t>(quantity >> 8));
    frame.push_back(static_cast<uint8_t>(quantity & 0xFF));
    frame.push_back(byte_count);
    for (uint8_t i = 0; i < byte_count; ++i) {
        uint8_t byte_val = 0;
        for (int bit = 0; bit < 8; ++bit) {
            size_t idx = static_cast<size_t>(i) * 8 + bit;
            if (idx < values.size() && values[idx]) {
                byte_val |= (1 << bit);
            }
        }
        frame.push_back(byte_val);
    }

    return frame;
}

std::vector<uint8_t> ModbusScanner::build_device_id_request(uint8_t unit_id) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return RtuFraming::build_read_device_id(unit_id,
                                                 static_cast<uint8_t>(ReadDeviceIdCode::BasicStream),
                                                 0x00);
    }

    // FC43 (0x2B) / MEI type 14 (0x0E) / ReadDeviceIdCode::BasicStream / ObjectId 0x00
    uint16_t tid = next_transaction_id();
    uint16_t pdu_len = 4;  // fc(1) + mei(1) + code(1) + obj(1)
    uint16_t mbap_length = 1 + pdu_len;

    std::vector<uint8_t> frame(7 + pdu_len);
    frame[0] = static_cast<uint8_t>(tid >> 8);
    frame[1] = static_cast<uint8_t>(tid & 0xFF);
    frame[2] = 0x00;
    frame[3] = 0x00;
    frame[4] = static_cast<uint8_t>(mbap_length >> 8);
    frame[5] = static_cast<uint8_t>(mbap_length & 0xFF);
    frame[6] = unit_id;
    frame[7] = 0x2B;  // FC43
    frame[8] = 0x0E;  // MEI type: Read Device Identification
    frame[9] = static_cast<uint8_t>(ReadDeviceIdCode::BasicStream);
    frame[10] = 0x00; // Start with object 0

    return frame;
}

std::vector<uint8_t> ModbusScanner::build_raw_fc_request(uint8_t unit_id, uint8_t fc,
                                                           const std::vector<uint8_t>& payload) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return RtuFraming::build_raw_fc(unit_id, fc, payload);
    }

    uint16_t tid = next_transaction_id();
    uint16_t pdu_len = 1 + static_cast<uint16_t>(payload.size());
    uint16_t mbap_length = 1 + pdu_len;

    std::vector<uint8_t> frame;
    frame.reserve(7 + pdu_len);
    frame.push_back(static_cast<uint8_t>(tid >> 8));
    frame.push_back(static_cast<uint8_t>(tid & 0xFF));
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(static_cast<uint8_t>(mbap_length >> 8));
    frame.push_back(static_cast<uint8_t>(mbap_length & 0xFF));
    frame.push_back(unit_id);
    frame.push_back(fc);
    frame.insert(frame.end(), payload.begin(), payload.end());

    return frame;
}

// ---------------------------------------------------------------------------
// Network I/O
// ---------------------------------------------------------------------------

static std::vector<uint8_t> do_send_receive_tcp(int fd, const std::vector<uint8_t>& request,
                                                  int timeout_ms) {
    if (fd < 0) return {};

    size_t total_sent = 0;
    while (total_sent < request.size()) {
        ssize_t sent = send(fd, request.data() + total_sent,
                            request.size() - total_sent, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return {};
        }
        total_sent += static_cast<size_t>(sent);
    }

    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int rv = poll(&pfd, 1, timeout_ms);
    if (rv <= 0) return {};

    // Read MBAP header (7 bytes)
    std::vector<uint8_t> header(7);
    size_t total_read = 0;
    while (total_read < 7) {
        ssize_t n = recv(fd, header.data() + total_read, 7 - total_read, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return {};
        }
        total_read += static_cast<size_t>(n);
    }

    uint16_t payload_len = (static_cast<uint16_t>(header[4]) << 8) | header[5];
    if (payload_len < 1 || payload_len > 260) return {};

    uint16_t pdu_len = payload_len - 1;
    std::vector<uint8_t> pdu(pdu_len);
    total_read = 0;
    while (total_read < pdu_len) {
        rv = poll(&pfd, 1, timeout_ms);
        if (rv <= 0) return {};

        ssize_t n = recv(fd, pdu.data() + total_read, pdu_len - total_read, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return {};
        }
        total_read += static_cast<size_t>(n);
    }

    std::vector<uint8_t> response;
    response.reserve(7 + pdu_len);
    response.insert(response.end(), header.begin(), header.end());
    response.insert(response.end(), pdu.begin(), pdu.end());
    return response;
}

static std::vector<uint8_t> do_send_receive_rtu(int fd, const std::vector<uint8_t>& request,
                                                  int timeout_ms) {
    if (fd < 0) return {};

    size_t total_sent = 0;
    while (total_sent < request.size()) {
        ssize_t sent = send(fd, request.data() + total_sent,
                            request.size() - total_sent, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return {};
        }
        total_sent += static_cast<size_t>(sent);
    }

    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int rv = poll(&pfd, 1, timeout_ms);
    if (rv <= 0) return {};

    // RTU over TCP: read up to 256 bytes (max RTU frame)
    std::vector<uint8_t> buf(260);
    size_t total_read = 0;

    // Read first chunk
    ssize_t n = recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) return {};
    total_read = static_cast<size_t>(n);

    // Brief wait for any remaining data
    rv = poll(&pfd, 1, 50);
    if (rv > 0) {
        n = recv(fd, buf.data() + total_read, buf.size() - total_read, 0);
        if (n > 0) total_read += static_cast<size_t>(n);
    }

    buf.resize(total_read);

    // Validate CRC
    if (!RtuFraming::validate_crc(buf)) return {};

    // Convert RTU response to look like a Modbus TCP response for unified parsing.
    // RTU: [unit_id(1)] [fc(1)] [data...] [crc(2)]
    // TCP: [MBAP(7)] [fc(1)] [data...]
    auto stripped = RtuFraming::strip_crc(buf);
    if (stripped.size() < 2) return {};

    uint8_t unit_id = stripped[0];
    uint16_t pdu_len = static_cast<uint16_t>(stripped.size() - 1);
    uint16_t mbap_len = 1 + pdu_len;

    std::vector<uint8_t> tcp_compat;
    tcp_compat.reserve(7 + pdu_len);
    tcp_compat.push_back(0x00);  // transaction ID
    tcp_compat.push_back(0x00);
    tcp_compat.push_back(0x00);  // protocol ID
    tcp_compat.push_back(0x00);
    tcp_compat.push_back(static_cast<uint8_t>(mbap_len >> 8));
    tcp_compat.push_back(static_cast<uint8_t>(mbap_len & 0xFF));
    tcp_compat.push_back(unit_id);
    tcp_compat.insert(tcp_compat.end(), stripped.begin() + 1, stripped.end());

    return tcp_compat;
}

std::vector<uint8_t> ModbusScanner::send_receive(const std::vector<uint8_t>& request) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return do_send_receive_rtu(sock_fd_, request, config_.timeout_ms);
    }
    return do_send_receive_tcp(sock_fd_, request, config_.timeout_ms);
}

std::vector<uint8_t> ModbusScanner::send_receive(int fd, const std::vector<uint8_t>& request) {
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        return do_send_receive_rtu(fd, request, config_.timeout_ms);
    }
    return do_send_receive_tcp(fd, request, config_.timeout_ms);
}

std::vector<uint8_t> ModbusScanner::send_receive_timed(const std::vector<uint8_t>& request,
                                                         double& elapsed_ms) {
    auto t0 = std::chrono::steady_clock::now();
    auto resp = send_receive(request);
    auto t1 = std::chrono::steady_clock::now();
    elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    return resp;
}
