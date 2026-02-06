// Unit tests for RTU framing and CRC-16/Modbus

#include "rtu_framing.h"

#define TEST_FRAMEWORK_NO_MAIN
#include "main_test.cpp"

using namespace modbus_probe;

// ===========================================================================
// CRC-16/Modbus computation
// ===========================================================================

TEST(crc16_known_vector) {
    // Known test vector: bytes {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A}
    // Expected CRC-16/Modbus: 0xC5CD
    std::vector<uint8_t> data = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    uint16_t crc = RtuFraming::crc16(data);
    ASSERT_EQ(crc, 0xC5CD);
}

TEST(crc16_single_byte) {
    std::vector<uint8_t> data = {0x00};
    uint16_t crc = RtuFraming::crc16(data);
    // CRC of single zero byte
    ASSERT_NE(crc, 0xFFFF);  // Should differ from initial value
}

TEST(crc16_empty_data) {
    std::vector<uint8_t> data;
    uint16_t crc = RtuFraming::crc16(data);
    ASSERT_EQ(crc, 0xFFFF);  // Initial value, no data processed
}

// ===========================================================================
// RTU frame building
// ===========================================================================

TEST(rtu_read_request_length) {
    // unit(1) + fc(1) + addr(2) + qty(2) + crc(2) = 8
    auto frame = RtuFraming::build_read_request(1, 0x03, 0, 10);
    ASSERT_EQ(frame.size(), 8u);
}

TEST(rtu_read_request_unit_id) {
    auto frame = RtuFraming::build_read_request(42, 0x03, 0, 10);
    ASSERT_EQ(frame[0], 42);
}

TEST(rtu_read_request_fc) {
    auto frame = RtuFraming::build_read_request(1, 0x04, 0, 10);
    ASSERT_EQ(frame[1], 0x04);
}

TEST(rtu_read_request_addr_big_endian) {
    auto frame = RtuFraming::build_read_request(1, 0x03, 0x1234, 1);
    ASSERT_EQ(frame[2], 0x12);
    ASSERT_EQ(frame[3], 0x34);
}

TEST(rtu_read_request_crc_valid) {
    auto frame = RtuFraming::build_read_request(1, 0x03, 0, 10);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

// ===========================================================================
// Write Single Coil (FC05)
// ===========================================================================

TEST(rtu_write_single_coil_on) {
    auto frame = RtuFraming::build_write_single_coil(1, 0x0010, true);
    ASSERT_EQ(frame.size(), 8u);
    ASSERT_EQ(frame[1], 0x05);
    ASSERT_EQ(frame[4], 0xFF);
    ASSERT_EQ(frame[5], 0x00);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

TEST(rtu_write_single_coil_off) {
    auto frame = RtuFraming::build_write_single_coil(1, 0x0010, false);
    ASSERT_EQ(frame[4], 0x00);
    ASSERT_EQ(frame[5], 0x00);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

// ===========================================================================
// Write Single Register (FC06)
// ===========================================================================

TEST(rtu_write_single_register) {
    auto frame = RtuFraming::build_write_single_register(1, 0x0001, 0xABCD);
    ASSERT_EQ(frame.size(), 8u);
    ASSERT_EQ(frame[1], 0x06);
    ASSERT_EQ(frame[4], 0xAB);
    ASSERT_EQ(frame[5], 0xCD);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

// ===========================================================================
// Write Multiple Coils (FC15)
// ===========================================================================

TEST(rtu_write_multiple_coils) {
    std::vector<bool> values = {true, false, true, true, false, false, true, true};
    auto frame = RtuFraming::build_write_multiple_coils(1, 0x0000, values);
    // unit(1) + fc(1) + addr(2) + qty(2) + byte_count(1) + data(1) + crc(2) = 10
    ASSERT_EQ(frame.size(), 10u);
    ASSERT_EQ(frame[1], 0x0F);
    ASSERT_EQ(frame[6], 0x01);  // byte count
    // Coil bits: 1101_1001 -> reversed bit order: bit0=1, bit1=0, bit2=1, bit3=1 etc.
    // = 0xCD
    ASSERT_EQ(frame[7], 0xCD);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

// ===========================================================================
// Write Multiple Registers (FC16)
// ===========================================================================

TEST(rtu_write_multiple_registers) {
    std::vector<uint16_t> values = {0x000A, 0x0102};
    auto frame = RtuFraming::build_write_multiple_registers(1, 0x0000, values);
    // unit(1) + fc(1) + addr(2) + qty(2) + byte_count(1) + data(4) + crc(2) = 13
    ASSERT_EQ(frame.size(), 13u);
    ASSERT_EQ(frame[1], 0x10);
    ASSERT_EQ(frame[6], 0x04);  // byte count
    ASSERT_EQ(frame[7], 0x00);  // value 1 high
    ASSERT_EQ(frame[8], 0x0A);  // value 1 low
    ASSERT_EQ(frame[9], 0x01);  // value 2 high
    ASSERT_EQ(frame[10], 0x02); // value 2 low
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

// ===========================================================================
// Device ID request (FC43/14)
// ===========================================================================

TEST(rtu_read_device_id) {
    auto frame = RtuFraming::build_read_device_id(1, 0x01, 0x00);
    // unit(1) + fc(1) + mei(1) + code(1) + obj(1) + crc(2) = 7
    ASSERT_EQ(frame.size(), 7u);
    ASSERT_EQ(frame[1], 0x2B);
    ASSERT_EQ(frame[2], 0x0E);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

// ===========================================================================
// Raw FC (for fuzzing)
// ===========================================================================

TEST(rtu_raw_fc_empty_payload) {
    auto frame = RtuFraming::build_raw_fc(1, 0x07, {});
    // unit(1) + fc(1) + crc(2) = 4
    ASSERT_EQ(frame.size(), 4u);
    ASSERT_EQ(frame[1], 0x07);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

TEST(rtu_raw_fc_with_payload) {
    auto frame = RtuFraming::build_raw_fc(1, 0x42, {0xAA, 0xBB});
    ASSERT_EQ(frame.size(), 6u);
    ASSERT_EQ(frame[2], 0xAA);
    ASSERT_EQ(frame[3], 0xBB);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
}

// ===========================================================================
// CRC validation and stripping
// ===========================================================================

TEST(validate_crc_detects_corruption) {
    auto frame = RtuFraming::build_read_request(1, 0x03, 0, 10);
    ASSERT_TRUE(RtuFraming::validate_crc(frame));
    // Corrupt one byte
    frame[3] ^= 0xFF;
    ASSERT_FALSE(RtuFraming::validate_crc(frame));
}

TEST(strip_crc_returns_payload) {
    auto frame = RtuFraming::build_read_request(1, 0x03, 0, 10);
    auto stripped = RtuFraming::strip_crc(frame);
    ASSERT_EQ(stripped.size(), frame.size() - 2);
    ASSERT_EQ(stripped[0], 1);    // unit ID
    ASSERT_EQ(stripped[1], 0x03); // FC
}

TEST(validate_crc_rejects_too_short) {
    std::vector<uint8_t> frame = {0x01, 0x03};
    ASSERT_FALSE(RtuFraming::validate_crc(frame));
}
