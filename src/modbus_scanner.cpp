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

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

bool ModbusScanner::is_exception_response(const std::vector<uint8_t>& response) const {
    if (response.size() < 9) return false;
    return (response[7] & 0x80) != 0;
}

ExceptionCode ModbusScanner::get_exception_code(const std::vector<uint8_t>& response) const {
    if (response.size() < 9) return ExceptionCode::SlaveDeviceFailure;
    return static_cast<ExceptionCode>(response[8]);
}

std::vector<uint16_t> ModbusScanner::parse_register_response(const std::vector<uint8_t>& response) {
    if (response.size() < 9) return {};
    if (is_exception_response(response)) return {};

    uint8_t byte_count = response[8];
    if (response.size() < static_cast<size_t>(9 + byte_count)) return {};

    std::vector<uint16_t> registers;
    registers.reserve(byte_count / 2);
    for (size_t i = 0; i < byte_count; i += 2) {
        uint16_t val = (static_cast<uint16_t>(response[9 + i]) << 8) |
                        response[9 + i + 1];
        registers.push_back(val);
    }
    return registers;
}

std::vector<bool> ModbusScanner::parse_coil_response(const std::vector<uint8_t>& response,
                                                      uint16_t count) {
    if (response.size() < 9) return {};
    if (is_exception_response(response)) return {};

    uint8_t byte_count = response[8];
    if (response.size() < static_cast<size_t>(9 + byte_count)) return {};

    std::vector<bool> coils;
    coils.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        size_t byte_idx = i / 8;
        uint8_t bit_idx = i % 8;
        if (byte_idx < byte_count) {
            bool val = (response[9 + byte_idx] >> bit_idx) & 0x01;
            coils.push_back(val);
        }
    }
    return coils;
}

DeviceIdentification ModbusScanner::parse_device_id_response(const std::vector<uint8_t>& response) {
    // Extract the PDU starting from byte 7 (after MBAP header)
    if (response.size() < 8) return {};
    std::vector<uint8_t> pdu(response.begin() + 7, response.end());
    return DeviceIdParser::parse_response(pdu);
}

// ---------------------------------------------------------------------------
// Scan operations
// ---------------------------------------------------------------------------

bool ModbusScanner::read_holding_registers(UnitResult& result) {
    auto req = build_request(result.unit_id, FunctionCode::ReadHoldingRegisters,
                             config_.register_start, config_.register_count);
    double elapsed = 0;
    auto resp = send_receive_timed(req, elapsed);
    result.timing_samples.push_back(elapsed);

    if (resp.empty()) return false;

    if (is_exception_response(resp)) {
        result.holding_registers_readable = false;
        return true;
    }

    auto regs = parse_register_response(resp);
    result.holding_registers_readable = !regs.empty();
    for (size_t i = 0; i < regs.size(); ++i) {
        result.holding_registers.push_back({
            static_cast<uint16_t>(config_.register_start + i),
            regs[i]
        });
    }
    return true;
}

bool ModbusScanner::read_input_registers(UnitResult& result) {
    auto req = build_request(result.unit_id, FunctionCode::ReadInputRegisters,
                             config_.register_start, config_.register_count);
    double elapsed = 0;
    auto resp = send_receive_timed(req, elapsed);
    result.timing_samples.push_back(elapsed);

    if (resp.empty()) return false;

    if (is_exception_response(resp)) {
        result.input_registers_readable = false;
        return true;
    }

    auto regs = parse_register_response(resp);
    result.input_registers_readable = !regs.empty();
    for (size_t i = 0; i < regs.size(); ++i) {
        result.input_registers.push_back({
            static_cast<uint16_t>(config_.register_start + i),
            regs[i]
        });
    }
    return true;
}

bool ModbusScanner::read_coils(UnitResult& result) {
    auto req = build_request(result.unit_id, FunctionCode::ReadCoils,
                             config_.coil_start, config_.coil_count);
    double elapsed = 0;
    auto resp = send_receive_timed(req, elapsed);
    result.timing_samples.push_back(elapsed);

    if (resp.empty()) return false;

    if (is_exception_response(resp)) {
        result.coils_readable = false;
        return true;
    }

    auto coils = parse_coil_response(resp, config_.coil_count);
    result.coils_readable = !coils.empty();
    for (size_t i = 0; i < coils.size(); ++i) {
        result.coils.push_back({
            static_cast<uint16_t>(config_.coil_start + i),
            coils[i]
        });
    }
    return true;
}

bool ModbusScanner::read_discrete_inputs(UnitResult& result) {
    auto req = build_request(result.unit_id, FunctionCode::ReadDiscreteInputs,
                             config_.coil_start, config_.coil_count);
    auto resp = send_receive(req);
    if (resp.empty()) return false;
    // We note success/failure but don't store discrete inputs separately
    // (they share the coils display in simplified mode)
    return true;
}

bool ModbusScanner::read_device_identification(UnitResult& result) {
    auto req = build_device_id_request(result.unit_id);
    auto resp = send_receive(req);
    if (resp.empty()) return false;

    if (is_exception_response(resp)) {
        result.device_id_supported = false;
        return true;
    }

    auto id = parse_device_id_response(resp);
    result.device_id_supported = id.supported;
    if (id.supported) {
        result.device_vendor = id.vendor_name;
        result.device_product_code = id.product_code;
        result.device_revision = id.revision;
        result.device_vendor_url = id.vendor_url;
        result.device_product_name = id.product_name;
        result.device_model_name = id.model_name;

        if (config_.verbose) {
            log("  Device ID: " + id.vendor_name + " / " + id.product_code +
                " / rev " + id.revision);
        }
    }
    return true;
}

bool ModbusScanner::scan_register_range(UnitResult& result, uint16_t start, uint16_t count) {
    // Scan a register range in chunks of 125 (Modbus maximum)
    const uint16_t max_per_request = 125;
    uint16_t remaining = count;
    uint16_t offset = 0;

    while (remaining > 0) {
        uint16_t chunk = std::min(remaining, max_per_request);
        auto req = build_request(result.unit_id, FunctionCode::ReadHoldingRegisters,
                                 start + offset, chunk);
        auto resp = send_receive(req);
        if (resp.empty()) return false;

        if (!is_exception_response(resp)) {
            auto regs = parse_register_response(resp);
            for (size_t i = 0; i < regs.size(); ++i) {
                result.holding_registers.push_back({
                    static_cast<uint16_t>(start + offset + i),
                    regs[i]
                });
            }
            result.holding_registers_readable = true;
        }

        offset += chunk;
        remaining -= chunk;
    }
    return true;
}

bool ModbusScanner::test_write_access(UnitResult& result) {
    result.write_test_performed = true;

    // Test FC06 (Write Single Register)
    uint16_t test_addr = config_.register_start;
    auto read_req = build_request(result.unit_id, FunctionCode::ReadHoldingRegisters,
                                   test_addr, 1);
    auto read_resp = send_receive(read_req);
    if (read_resp.empty() || is_exception_response(read_resp)) {
        result.write_test_vulnerable = false;
        result.write_test_detail = "Could not read register for write test";
        return true;
    }

    auto original_vals = parse_register_response(read_resp);
    if (original_vals.empty()) {
        result.write_test_vulnerable = false;
        result.write_test_detail = "Failed to parse register value";
        return true;
    }

    uint16_t original_value = original_vals[0];
    uint16_t test_value = original_value ^ 0x0001;

    // Attempt write
    auto write_req = build_write_single_register(result.unit_id, test_addr, test_value);
    auto write_resp = send_receive(write_req);

    if (write_resp.empty()) {
        result.write_test_vulnerable = false;
        result.write_test_detail = "No response to write request (connection may have been rejected)";
        return true;
    }

    if (is_exception_response(write_resp)) {
        auto ec = get_exception_code(write_resp);
        result.write_test_vulnerable = false;
        std::ostringstream os;
        os << "Write rejected with exception code 0x"
           << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<int>(ec);
        result.write_test_detail = os.str();
        return true;
    }

    // Write succeeded -- vulnerability
    result.write_test_vulnerable = true;

    // Rollback
    auto rollback_req = build_write_single_register(result.unit_id, test_addr, original_value);
    auto rollback_resp = send_receive(rollback_req);

    if (rollback_resp.empty() || is_exception_response(rollback_resp)) {
        std::ostringstream os;
        os << "CRITICAL: Write succeeded (addr=" << test_addr
           << " value=0x" << std::hex << test_value
           << ") but rollback to 0x" << original_value << " FAILED";
        result.write_test_detail = os.str();
        log("[!] " + result.write_test_detail);
    } else {
        auto verify_req = build_request(result.unit_id, FunctionCode::ReadHoldingRegisters,
                                         test_addr, 1);
        auto verify_resp = send_receive(verify_req);
        auto verify_vals = parse_register_response(verify_resp);

        if (!verify_vals.empty() && verify_vals[0] == original_value) {
            std::ostringstream os;
            os << "Unauthorized write succeeded and was rolled back (addr="
               << std::dec << test_addr << ")";
            result.write_test_detail = os.str();
        } else {
            std::ostringstream os;
            os << "Unauthorized write succeeded, rollback unverified (addr="
               << std::dec << test_addr << ")";
            result.write_test_detail = os.str();
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Finding classification
// ---------------------------------------------------------------------------

void ModbusScanner::classify_findings(UnitResult& result) {
    if (result.write_test_vulnerable) {
        result.findings.push_back({
            FindingSeverity::CRITICAL,
            "unauthorized_write",
            "Unauthenticated write access via FC06: " + result.write_test_detail
        });
    }
    if (result.holding_registers_readable) {
        result.findings.push_back({
            FindingSeverity::HIGH,
            "unauthorized_read",
            "Holding registers readable without authentication (FC03)"
        });
    }
    if (result.input_registers_readable) {
        result.findings.push_back({
            FindingSeverity::HIGH,
            "unauthorized_read",
            "Input registers readable without authentication (FC04)"
        });
    }
    if (result.coils_readable) {
        result.findings.push_back({
            FindingSeverity::HIGH,
            "unauthorized_read",
            "Coils readable without authentication (FC01)"
        });
    }
    if (result.device_id_supported) {
        result.findings.push_back({
            FindingSeverity::MEDIUM,
            "device_info_leak",
            "Device identification data exposed via FC43/14"
        });
    }
    if (result.responsive && result.findings.empty()) {
        result.findings.push_back({
            FindingSeverity::INFO,
            "device_responsive",
            "Unit responds to Modbus requests"
        });
    }
}

// ---------------------------------------------------------------------------
// Unit scanning
// ---------------------------------------------------------------------------

UnitResult ModbusScanner::scan_unit(uint8_t unit_id) {
    UnitResult result{};
    result.unit_id = unit_id;
    result.responsive = false;
    result.holding_registers_readable = false;
    result.input_registers_readable = false;
    result.coils_readable = false;
    result.write_test_performed = false;
    result.write_test_vulnerable = false;

    // Liveness probe
    auto req = build_request(unit_id, FunctionCode::ReadHoldingRegisters,
                             config_.register_start, 1);
    double probe_elapsed = 0;
    auto resp = send_receive_timed(req, probe_elapsed);

    if (resp.empty()) return result;

    result.responsive = true;
    result.timing_samples.push_back(probe_elapsed);

    ui_.print_status(Severity::PASS, "Unit ID " + std::to_string(unit_id) + " is responsive");

    // Full reads
    if (!read_holding_registers(result)) {
        if (tcp_connect()) {
            read_holding_registers(result);
        }
    }

    read_input_registers(result);
    read_coils(result);

    // Extra register ranges
    for (const auto& range : config_.extra_ranges) {
        scan_register_range(result, range.start, range.count);
    }

    // Device identification
    if (config_.read_device_id) {
        read_device_identification(result);
    }

    // Write test
    if (config_.test_write) {
        test_write_access(result);
    }

    // Classify
    classify_findings(result);

    return result;
}

// ---------------------------------------------------------------------------
// Function code fuzzing
// ---------------------------------------------------------------------------

FuzzEntry ModbusScanner::fuzz_single_fc(int fd, uint8_t unit_id, uint8_t fc) {
    FuzzEntry entry{};
    entry.function_code = fc;
    entry.description = FunctionCodeFuzzer::fc_name(fc);

    // Build a minimal request for this FC
    // For read-like FCs, use addr=0 qty=1; for others, just send the FC bare
    std::vector<uint8_t> payload;
    if (fc >= 0x01 && fc <= 0x04) {
        // Read FCs: need start_addr(2) + quantity(2)
        payload = {0x00, 0x00, 0x00, 0x01};
    } else if (fc == 0x05) {
        payload = {0x00, 0x00, 0x00, 0x00};  // coil addr + OFF
    } else if (fc == 0x06) {
        payload = {0x00, 0x00, 0x00, 0x00};  // reg addr + value 0
    } else if (fc == 0x2B) {
        payload = {0x0E, 0x01, 0x00};  // MEI, BasicStream, obj 0
    }

    std::vector<uint8_t> request;
    if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
        request = RtuFraming::build_raw_fc(unit_id, fc, payload);
    } else {
        request = build_raw_fc_request(unit_id, fc, payload);
    }

    auto t0 = std::chrono::steady_clock::now();
    auto resp = send_receive(fd, request);
    auto t1 = std::chrono::steady_clock::now();
    entry.response_time_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    if (resp.empty()) {
        entry.result_type = FuzzResultType::Timeout;
        entry.description += " -> TIMEOUT";
    } else if (is_exception_response(resp)) {
        entry.result_type = FuzzResultType::Exception;
        entry.exception_code = static_cast<uint8_t>(get_exception_code(resp));
        entry.description += " -> Exception: " + FunctionCodeFuzzer::exception_name(entry.exception_code);
    } else {
        entry.result_type = FuzzResultType::Supported;
        entry.description += " -> Supported";
    }

    return entry;
}

FuzzReport ModbusScanner::run_fuzz(uint8_t unit_id) {
    FuzzReport report{};
    report.unit_id = unit_id;
    report.total_tested = 0;

    int fd = -1;
    if (!tcp_connect(fd)) {
        log("[!] Failed to connect for fuzzing");
        return report;
    }

    ui_.print_section("Function Code Fuzzing (Unit " + std::to_string(unit_id) + ")");

    for (uint8_t fc = 1; fc <= 127; ++fc) {
        auto entry = fuzz_single_fc(fd, unit_id, fc);
        report.entries.push_back(entry);
        ++report.total_tested;

        switch (entry.result_type) {
            case FuzzResultType::Supported:  ++report.supported_count; break;
            case FuzzResultType::Exception:  ++report.exception_count; break;
            case FuzzResultType::Timeout:    ++report.timeout_count;   break;
            case FuzzResultType::Error:      ++report.error_count;     break;
        }

        if (!config_.quiet) {
            ui_.print_progress(fc, 127, "Fuzzing FC");
        }

        // Brief pause to avoid overwhelming the device
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    tcp_disconnect(fd);
    return report;
}

// ---------------------------------------------------------------------------
// Main scan orchestrator
// ---------------------------------------------------------------------------

ScanReport ModbusScanner::run() {
    ScanReport report;
    report.target_host = config_.host;
    report.target_port = config_.port;
    report.tool_version = "2.0.0";
    report.protocol_mode = (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) ? "rtu_over_tcp" : "tcp";
    report.thread_count = static_cast<uint32_t>(config_.thread_count);
    report.scan_start = current_timestamp();
    report.devices_identified = 0;

    ui_.print_banner();

    std::string proto_str = (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP)
        ? "RTU-over-TCP" : "Modbus TCP";
    ui_.print_status(Severity::INFO, "Target: " + config_.host + ":" + std::to_string(config_.port));
    ui_.print_status(Severity::INFO, "Protocol: " + proto_str);
    ui_.print_status(Severity::INFO, "Scanning unit IDs " + std::to_string(config_.id_start) +
        "-" + std::to_string(config_.id_end));
    if (config_.thread_count > 1) {
        ui_.print_status(Severity::INFO, "Threads: " + std::to_string(config_.thread_count));
    }
    if (config_.test_write) {
        ui_.print_status(Severity::WARN, "Write testing ENABLED (with rollback)");
    }
    if (config_.fuzz_function_codes) {
        ui_.print_status(Severity::WARN, "Function code fuzzing ENABLED");
    }

    if (!tcp_connect()) {
        ui_.print_status(Severity::FAIL, "Failed to connect to " + config_.host + ":" +
            std::to_string(config_.port));
        report.scan_end = current_timestamp();
        return report;
    }
    ui_.print_status(Severity::PASS, "Connected to target");

    uint32_t total_ids = static_cast<uint32_t>(config_.id_end) - config_.id_start + 1;
    std::vector<UnitResult> all_results;
    std::mutex results_mutex;

    if (config_.thread_count <= 1) {
        // Single-threaded scan
        for (int id = config_.id_start; id <= config_.id_end; ++id) {
            auto result = scan_unit(static_cast<uint8_t>(id));
            if (result.responsive) {
                all_results.push_back(std::move(result));
            }
            progress_current_++;
            if (!config_.quiet && !config_.verbose) {
                ui_.print_progress(progress_current_.load(), total_ids, "Scanning");
            }
        }
    } else {
        // Multi-threaded scan
        tcp_disconnect();  // close the probe connection; each thread gets its own

        std::vector<uint8_t> unit_ids;
        for (int id = config_.id_start; id <= config_.id_end; ++id) {
            unit_ids.push_back(static_cast<uint8_t>(id));
        }

        // Partition work across threads
        auto worker = [&](size_t start_idx, size_t end_idx) {
            int fd = -1;
            if (!tcp_connect(fd)) return;

            for (size_t i = start_idx; i < end_idx; ++i) {
                uint8_t uid = unit_ids[i];

                // Build and send liveness probe on this fd
                std::vector<uint8_t> req;
                if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
                    req = RtuFraming::build_read_request(uid, 0x03, config_.register_start, 1);
                } else {
                    uint16_t tid;
                    {
                        std::lock_guard<std::mutex> lock(tid_mutex_);
                        tid = ++transaction_counter_;
                    }
                    req.resize(12);
                    req[0] = static_cast<uint8_t>(tid >> 8);
                    req[1] = static_cast<uint8_t>(tid & 0xFF);
                    req[2] = 0x00; req[3] = 0x00;
                    req[4] = 0x00; req[5] = 0x06;
                    req[6] = uid;
                    req[7] = 0x03;
                    req[8] = static_cast<uint8_t>(config_.register_start >> 8);
                    req[9] = static_cast<uint8_t>(config_.register_start & 0xFF);
                    req[10] = 0x00; req[11] = 0x01;
                }

                auto resp = send_receive(fd, req);
                progress_current_++;
                if (!config_.quiet && !config_.verbose) {
                    ui_.print_progress(progress_current_.load(), total_ids, "Scanning");
                }

                if (!resp.empty()) {
                    // Responsive -- do full scan on a dedicated connection
                    // (some devices behave differently with interleaved unit IDs)
                    int scan_fd = -1;
                    if (tcp_connect(scan_fd)) {
                        // Use the main scan path but save/restore sock_fd_
                        // For thread safety, we'll do a simplified inline scan
                        UnitResult result{};
                        result.unit_id = uid;
                        result.responsive = true;
                        result.holding_registers_readable = false;
                        result.input_registers_readable = false;
                        result.coils_readable = false;
                        result.write_test_performed = false;
                        result.write_test_vulnerable = false;

                        // Helper lambdas for scanning on scan_fd
                        auto sr = [&](const std::vector<uint8_t>& r) {
                            return send_receive(scan_fd, r);
                        };

                        // Read holding registers
                        {
                            std::vector<uint8_t> rreq;
                            if (config_.protocol_mode == ProtocolMode::RTU_OVER_TCP) {
                                rreq = RtuFraming::build_read_request(uid, 0x03,
                                    config_.register_start, config_.register_count);
                            } else {
                                rreq = build_request(uid, FunctionCode::ReadHoldingRegisters,
                                    config_.register_start, config_.register_count);
                            }
                            auto rresp = sr(rreq);
                            if (!rresp.empty() && !is_exception_response(rresp)) {
                                auto regs = parse_register_response(rresp);
                                result.holding_registers_readable = !regs.empty();
                                for (size_t j = 0; j < regs.size(); ++j) {
                                    result.holding_registers.push_back({
                                        static_cast<uint16_t>(config_.register_start + j),
                                        regs[j]
                                    });
                                }
                            }
                        }

                        // Read input registers
                        {
                            auto rreq = build_request(uid, FunctionCode::ReadInputRegisters,
                                config_.register_start, config_.register_count);
                            auto rresp = sr(rreq);
                            if (!rresp.empty() && !is_exception_response(rresp)) {
                                auto regs = parse_register_response(rresp);
                                result.input_registers_readable = !regs.empty();
                                for (size_t j = 0; j < regs.size(); ++j) {
                                    result.input_registers.push_back({
                                        static_cast<uint16_t>(config_.register_start + j),
                                        regs[j]
                                    });
                                }
                            }
                        }

                        // Read coils
                        {
                            auto rreq = build_request(uid, FunctionCode::ReadCoils,
                                config_.coil_start, config_.coil_count);
                            auto rresp = sr(rreq);
                            if (!rresp.empty() && !is_exception_response(rresp)) {
                                auto coils = parse_coil_response(rresp, config_.coil_count);
                                result.coils_readable = !coils.empty();
                                for (size_t j = 0; j < coils.size(); ++j) {
                                    result.coils.push_back({
                                        static_cast<uint16_t>(config_.coil_start + j),
                                        coils[j]
                                    });
                                }
                            }
                        }

                        // Device ID
                        if (config_.read_device_id) {
                            auto rreq = build_device_id_request(uid);
                            auto rresp = sr(rreq);
                            if (!rresp.empty() && !is_exception_response(rresp)) {
                                auto did = parse_device_id_response(rresp);
                                result.device_id_supported = did.supported;
                                if (did.supported) {
                                    result.device_vendor = did.vendor_name;
                                    result.device_product_code = did.product_code;
                                    result.device_revision = did.revision;
                                    result.device_vendor_url = did.vendor_url;
                                    result.device_product_name = did.product_name;
                                    result.device_model_name = did.model_name;
                                }
                            }
                        }

                        classify_findings(result);

                        {
                            std::lock_guard<std::mutex> lock(results_mutex);
                            all_results.push_back(std::move(result));
                        }

                        tcp_disconnect(scan_fd);
                    }
                }
            }

            tcp_disconnect(fd);
        };

        // Launch threads
        size_t n_ids = unit_ids.size();
        size_t n_threads = static_cast<size_t>(config_.thread_count);
        if (n_threads > n_ids) n_threads = n_ids;
        size_t chunk = n_ids / n_threads;

        std::vector<std::thread> threads;
        for (size_t t = 0; t < n_threads; ++t) {
            size_t start_idx = t * chunk;
            size_t end_idx = (t + 1 == n_threads) ? n_ids : (t + 1) * chunk;
            threads.emplace_back(worker, start_idx, end_idx);
        }
        for (auto& th : threads) {
            th.join();
        }

        // Sort results by unit ID
        std::sort(all_results.begin(), all_results.end(),
                  [](const UnitResult& a, const UnitResult& b) {
                      return a.unit_id < b.unit_id;
                  });
    }

    tcp_disconnect();

    // Aggregate stats
    uint32_t scanned = total_ids;
    uint32_t responsive = 0;
    uint32_t unauth_reads = 0;
    uint32_t unauth_writes = 0;
    uint32_t devices_id = 0;

    for (const auto& r : all_results) {
        if (r.responsive) {
            ++responsive;
            if (r.holding_registers_readable || r.input_registers_readable ||
                r.coils_readable) {
                ++unauth_reads;
            }
            if (r.write_test_vulnerable) {
                ++unauth_writes;
                ui_.print_status(Severity::CRITICAL,
                    "VULNERABLE: Unit " + std::to_string(r.unit_id) +
                    " allows unauthenticated writes");
            }
            if (r.device_id_supported) {
                ++devices_id;
            }
        }
    }

    report.results = std::move(all_results);
    report.units_scanned = scanned;
    report.units_responsive = responsive;
    report.unauthenticated_reads = unauth_reads;
    report.unauthenticated_writes = unauth_writes;
    report.devices_identified = devices_id;
    report.scan_end = current_timestamp();

    // Print summary
    ui_.print_section("Scan Complete");
    ui_.print_status(Severity::INFO, "Units scanned:           " + std::to_string(scanned));
    ui_.print_status(Severity::INFO, "Units responsive:        " + std::to_string(responsive));

    if (unauth_reads > 0) {
        ui_.print_status(Severity::WARN, "Unauthenticated reads:   " + std::to_string(unauth_reads));
    } else {
        ui_.print_status(Severity::PASS, "Unauthenticated reads:   0");
    }

    if (unauth_writes > 0) {
        ui_.print_status(Severity::CRITICAL, "Unauthenticated writes:  " + std::to_string(unauth_writes));
    } else {
        ui_.print_status(Severity::PASS, "Unauthenticated writes:  0");
    }

    if (devices_id > 0) {
        ui_.print_status(Severity::WARN, "Devices identified:      " + std::to_string(devices_id));
    }

    return report;
}

}  // namespace modbus_probe
