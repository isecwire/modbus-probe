#include "rtu_framing.h"

namespace modbus_probe {

// ---------------------------------------------------------------------------
// CRC-16/Modbus -- reflected polynomial 0xA001
//
// Uses a precomputed 256-entry lookup table for ~4x speedup over the
// naive bit-by-bit implementation. The table is generated at compile time
// using constexpr.
// ---------------------------------------------------------------------------

namespace {

// Constexpr CRC table generation
constexpr uint16_t crc16_compute_entry(uint16_t byte_val) {
    uint16_t crc = byte_val;
    for (int bit = 0; bit < 8; ++bit) {
        if (crc & 0x0001) {
            crc = (crc >> 1) ^ 0xA001;
        } else {
            crc >>= 1;
        }
    }
    return crc;
}

struct Crc16Table {
    uint16_t entries[256];
    constexpr Crc16Table() : entries{} {
        for (uint16_t i = 0; i < 256; ++i) {
            entries[i] = crc16_compute_entry(i);
        }
    }
};

constexpr Crc16Table CRC_TABLE{};

}  // anonymous namespace

uint16_t RtuFraming::crc16(const uint8_t* data, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; ++i) {
        uint8_t index = static_cast<uint8_t>(crc ^ data[i]);
        crc = (crc >> 8) ^ CRC_TABLE.entries[index];
    }
    return crc;
}

uint16_t RtuFraming::crc16(const std::vector<uint8_t>& data) {
    return crc16(data.data(), data.size());
}

void RtuFraming::append_crc(std::vector<uint8_t>& frame) {
    uint16_t crc = crc16(frame.data(), frame.size());
    frame.push_back(static_cast<uint8_t>(crc & 0xFF));        // CRC low byte
    frame.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF)); // CRC high byte
}

bool RtuFraming::validate_crc(const std::vector<uint8_t>& frame) {
    if (frame.size() < 4) return false;  // minimum: unit(1) + fc(1) + crc(2)
    uint16_t received = static_cast<uint16_t>(frame[frame.size() - 2]) |
                        (static_cast<uint16_t>(frame[frame.size() - 1]) << 8);
    uint16_t computed = crc16(frame.data(), frame.size() - 2);
    return received == computed;
}

std::vector<uint8_t> RtuFraming::strip_crc(const std::vector<uint8_t>& frame) {
    if (frame.size() < 4) return {};
    return std::vector<uint8_t>(frame.begin(), frame.end() - 2);
}

// ---------------------------------------------------------------------------
// Frame builders
// ---------------------------------------------------------------------------

std::vector<uint8_t> RtuFraming::build_read_request(uint8_t unit_id,
                                                      uint8_t function_code,
                                                      uint16_t start_addr,
                                                      uint16_t quantity) {
    std::vector<uint8_t> frame;
    frame.reserve(8);  // unit(1) + fc(1) + addr(2) + qty(2) + crc(2)
    frame.push_back(unit_id);
    frame.push_back(function_code);
    frame.push_back(static_cast<uint8_t>(start_addr >> 8));
    frame.push_back(static_cast<uint8_t>(start_addr & 0xFF));
    frame.push_back(static_cast<uint8_t>(quantity >> 8));
    frame.push_back(static_cast<uint8_t>(quantity & 0xFF));
    append_crc(frame);
    return frame;
}

std::vector<uint8_t> RtuFraming::build_write_single_coil(uint8_t unit_id,
                                                           uint16_t addr,
                                                           bool value) {
    std::vector<uint8_t> frame;
    frame.reserve(8);
    frame.push_back(unit_id);
    frame.push_back(0x05);
    frame.push_back(static_cast<uint8_t>(addr >> 8));
    frame.push_back(static_cast<uint8_t>(addr & 0xFF));
    frame.push_back(value ? 0xFF : 0x00);
    frame.push_back(0x00);
    append_crc(frame);
    return frame;
}

std::vector<uint8_t> RtuFraming::build_write_single_register(uint8_t unit_id,
                                                               uint16_t addr,
                                                               uint16_t value) {
    std::vector<uint8_t> frame;
    frame.reserve(8);
    frame.push_back(unit_id);
    frame.push_back(0x06);
    frame.push_back(static_cast<uint8_t>(addr >> 8));
    frame.push_back(static_cast<uint8_t>(addr & 0xFF));
    frame.push_back(static_cast<uint8_t>(value >> 8));
    frame.push_back(static_cast<uint8_t>(value & 0xFF));
    append_crc(frame);
    return frame;
}

std::vector<uint8_t> RtuFraming::build_write_multiple_coils(uint8_t unit_id,
                                                              uint16_t start_addr,
                                                              const std::vector<bool>& values) {
    // FC15: unit(1) + fc(1) + addr(2) + qty(2) + byte_count(1) + data(N) + crc(2)
    uint16_t quantity = static_cast<uint16_t>(values.size());
    uint8_t byte_count = static_cast<uint8_t>((quantity + 7) / 8);

    std::vector<uint8_t> frame;
    frame.reserve(7 + byte_count + 2);
    frame.push_back(unit_id);
    frame.push_back(0x0F);
    frame.push_back(static_cast<uint8_t>(start_addr >> 8));
    frame.push_back(static_cast<uint8_t>(start_addr & 0xFF));
    frame.push_back(static_cast<uint8_t>(quantity >> 8));
    frame.push_back(static_cast<uint8_t>(quantity & 0xFF));
    frame.push_back(byte_count);

    // Pack coil bits
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

    append_crc(frame);
    return frame;
}

std::vector<uint8_t> RtuFraming::build_write_multiple_registers(uint8_t unit_id,
                                                                  uint16_t start_addr,
                                                                  const std::vector<uint16_t>& values) {
    // FC16: unit(1) + fc(1) + addr(2) + qty(2) + byte_count(1) + data(N*2) + crc(2)
    uint16_t quantity = static_cast<uint16_t>(values.size());
    uint8_t byte_count = static_cast<uint8_t>(quantity * 2);

    std::vector<uint8_t> frame;
    frame.reserve(7 + byte_count + 2);
    frame.push_back(unit_id);
    frame.push_back(0x10);
    frame.push_back(static_cast<uint8_t>(start_addr >> 8));
    frame.push_back(static_cast<uint8_t>(start_addr & 0xFF));
    frame.push_back(static_cast<uint8_t>(quantity >> 8));
    frame.push_back(static_cast<uint8_t>(quantity & 0xFF));
    frame.push_back(byte_count);

    for (auto val : values) {
        frame.push_back(static_cast<uint8_t>(val >> 8));
        frame.push_back(static_cast<uint8_t>(val & 0xFF));
    }

    append_crc(frame);
    return frame;
}

std::vector<uint8_t> RtuFraming::build_read_device_id(uint8_t unit_id,
                                                        uint8_t read_device_id_code,
                                                        uint8_t object_id) {
    // FC43 (0x2B) / MEI type 14 (0x0E)
    std::vector<uint8_t> frame;
    frame.reserve(7);  // unit(1) + fc(1) + mei(1) + code(1) + obj(1) + crc(2)
    frame.push_back(unit_id);
    frame.push_back(0x2B);       // FC43
    frame.push_back(0x0E);       // MEI type: Read Device Identification
    frame.push_back(read_device_id_code);
    frame.push_back(object_id);
    append_crc(frame);
    return frame;
}

std::vector<uint8_t> RtuFraming::build_raw_fc(uint8_t unit_id,
                                                uint8_t function_code,
                                                const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    frame.reserve(2 + payload.size() + 2);
    frame.push_back(unit_id);
    frame.push_back(function_code);
    frame.insert(frame.end(), payload.begin(), payload.end());
    append_crc(frame);
    return frame;
}

}  // namespace modbus_probe
