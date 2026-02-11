// Unit tests for ModbusScanner -- frame building, parsing, and protocol logic

// Allow access to private members for testing.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wkeyword-macro"
#define private public
#define protected public
#pragma GCC diagnostic pop

#include "modbus_scanner.h"

#undef private
#undef protected

#define TEST_FRAMEWORK_NO_MAIN
#include "main_test.cpp"

using namespace modbus_probe;

// ---------------------------------------------------------------------------
// Helper: create a scanner with default config (no real connection needed)
// ---------------------------------------------------------------------------
static ModbusScanner make_scanner() {
    ScanConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 502;
    cfg.register_start = 0;
    cfg.register_count = 10;
    cfg.coil_start = 0;
    cfg.coil_count = 16;
    cfg.timeout_ms = 1000;
    cfg.protocol_mode = ProtocolMode::TCP;
    cfg.color = false;
    cfg.quiet = true;
    return ModbusScanner(cfg);
}

// ===========================================================================
// MBAP header construction
// ===========================================================================

TEST(mbap_header_total_length) {
    auto scanner = make_scanner();
    auto frame = scanner.build_request(1, FunctionCode::ReadHoldingRegisters, 0, 10);
    ASSERT_EQ(frame.size(), 12u);
}

TEST(mbap_header_protocol_id_is_zero) {
    auto scanner = make_scanner();
    auto frame = scanner.build_request(1, FunctionCode::ReadCoils, 0, 16);
    ASSERT_EQ(frame[2], 0x00);
    ASSERT_EQ(frame[3], 0x00);
}

TEST(mbap_header_length_field) {
    auto scanner = make_scanner();
    auto frame = scanner.build_request(1, FunctionCode::ReadHoldingRegisters, 0, 10);
    uint16_t length = (static_cast<uint16_t>(frame[4]) << 8) | frame[5];
    ASSERT_EQ(length, 6u);
}

TEST(mbap_header_unit_id) {
    auto scanner = make_scanner();
    auto frame = scanner.build_request(42, FunctionCode::ReadInputRegisters, 0, 5);
    ASSERT_EQ(frame[6], 42);
}

TEST(mbap_header_transaction_id_increments) {
    auto scanner = make_scanner();
    auto f1 = scanner.build_request(1, FunctionCode::ReadCoils, 0, 1);
    auto f2 = scanner.build_request(1, FunctionCode::ReadCoils, 0, 1);
    uint16_t tid1 = (static_cast<uint16_t>(f1[0]) << 8) | f1[1];
    uint16_t tid2 = (static_cast<uint16_t>(f2[0]) << 8) | f2[1];
    ASSERT_EQ(tid2, tid1 + 1);
}

TEST(mbap_header_big_endian_transaction_id) {
    auto scanner = make_scanner();
    scanner.transaction_counter_ = 0x00FE;
    auto frame = scanner.build_request(1, FunctionCode::ReadCoils, 0, 1);
    ASSERT_EQ(frame[0], 0x00);
    ASSERT_EQ(frame[1], 0xFF);
}

// ===========================================================================
// PDU building for different function codes
// ===========================================================================

TEST(pdu_fc01_read_coils) {
    auto scanner = make_scanner();
    auto frame = scanner.build_request(1, FunctionCode::ReadCoils, 0x0010, 0x0025);
    ASSERT_EQ(frame[7], 0x01);
    ASSERT_EQ(frame[8], 0x00);
    ASSERT_EQ(frame[9], 0x10);
    ASSERT_EQ(frame[10], 0x00);
    ASSERT_EQ(frame[11], 0x25);
}

TEST(pdu_fc03_read_holding_registers) {
    auto scanner = make_scanner();
    auto frame = scanner.build_request(1, FunctionCode::ReadHoldingRegisters, 100, 5);
    ASSERT_EQ(frame[7], 0x03);
    ASSERT_EQ(frame[8], 0x00);
    ASSERT_EQ(frame[9], 0x64);
    ASSERT_EQ(frame[10], 0x00);
    ASSERT_EQ(frame[11], 0x05);
}

TEST(pdu_fc04_read_input_registers) {
    auto scanner = make_scanner();
    auto frame = scanner.build_request(1, FunctionCode::ReadInputRegisters, 0, 10);
    ASSERT_EQ(frame[7], 0x04);
}

TEST(pdu_fc06_write_single_register) {
    auto scanner = make_scanner();
    auto frame = scanner.build_write_single_register(7, 0x0001, 0xABCD);
    ASSERT_EQ(frame.size(), 12u);
    ASSERT_EQ(frame[6], 7);
    ASSERT_EQ(frame[7], 0x06);
    ASSERT_EQ(frame[8], 0x00);
    ASSERT_EQ(frame[9], 0x01);
    ASSERT_EQ(frame[10], 0xAB);
    ASSERT_EQ(frame[11], 0xCD);
}

TEST(pdu_fc06_length_field_correct) {
    auto scanner = make_scanner();
    auto frame = scanner.build_write_single_register(1, 0, 0);
    uint16_t length = (static_cast<uint16_t>(frame[4]) << 8) | frame[5];
    ASSERT_EQ(length, 6u);
}

TEST(pdu_address_big_endian) {
    auto scanner = make_scanner();
    auto frame = scanner.build_request(1, FunctionCode::ReadHoldingRegisters, 0x1234, 0x0001);
    ASSERT_EQ(frame[8], 0x12);
    ASSERT_EQ(frame[9], 0x34);
}

// ===========================================================================
// FC05 Write Single Coil
// ===========================================================================

TEST(pdu_fc05_write_single_coil_on) {
    auto scanner = make_scanner();
    auto frame = scanner.build_write_single_coil(1, 0x0010, true);
    ASSERT_EQ(frame.size(), 12u);
    ASSERT_EQ(frame[7], 0x05);
    ASSERT_EQ(frame[10], 0xFF);
    ASSERT_EQ(frame[11], 0x00);
}

TEST(pdu_fc05_write_single_coil_off) {
    auto scanner = make_scanner();
    auto frame = scanner.build_write_single_coil(1, 0x0010, false);
    ASSERT_EQ(frame[10], 0x00);
    ASSERT_EQ(frame[11], 0x00);
}

// ===========================================================================
// FC16 Write Multiple Registers
// ===========================================================================

TEST(pdu_fc16_write_multiple_registers) {
    auto scanner = make_scanner();
    std::vector<uint16_t> values = {0x0001, 0x0002, 0x0003};
    auto frame = scanner.build_write_multiple_registers(1, 0x0000, values);
    // MBAP(7) + FC(1) + addr(2) + qty(2) + byte_count(1) + data(6) = 19
    ASSERT_EQ(frame.size(), 19u);
    ASSERT_EQ(frame[7], 0x10);  // FC16
    ASSERT_EQ(frame[12], 0x06); // byte count = 3 regs * 2
}

// ===========================================================================
// FC43/14 Device ID request
// ===========================================================================

TEST(build_device_id_request_structure) {
    auto scanner = make_scanner();
    auto frame = scanner.build_device_id_request(1);
    ASSERT_EQ(frame[7], 0x2B);  // FC43
    ASSERT_EQ(frame[8], 0x0E);  // MEI type
}

// ===========================================================================
// Raw FC request (for fuzzing)
// ===========================================================================

TEST(build_raw_fc_request_basic) {
    auto scanner = make_scanner();
    auto frame = scanner.build_raw_fc_request(1, 0x07, {});
    // MBAP(7) + FC(1) = 8 bytes minimum
    ASSERT_GE(frame.size(), 8u);
    ASSERT_EQ(frame[7], 0x07);
}

TEST(build_raw_fc_request_with_payload) {
    auto scanner = make_scanner();
    std::vector<uint8_t> payload = {0xAA, 0xBB};
    auto frame = scanner.build_raw_fc_request(1, 0x42, payload);
    ASSERT_EQ(frame.size(), 10u);  // MBAP(7) + FC(1) + payload(2)
    ASSERT_EQ(frame[7], 0x42);
    ASSERT_EQ(frame[8], 0xAA);
    ASSERT_EQ(frame[9], 0xBB);
}

// ===========================================================================
// Exception response parsing
// ===========================================================================

TEST(exception_response_detected) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
        0x01, 0x83, 0x02
    };
    ASSERT_TRUE(scanner.is_exception_response(resp));
}

TEST(exception_response_code_extraction) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
        0x01, 0x83, 0x02
    };
    auto code = scanner.get_exception_code(resp);
    ASSERT_EQ(static_cast<uint8_t>(code), 0x02);
}

TEST(exception_response_illegal_function) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
        0x01, 0x81, 0x01
    };
    ASSERT_TRUE(scanner.is_exception_response(resp));
    auto code = scanner.get_exception_code(resp);
    ASSERT_EQ(code, ExceptionCode::IllegalFunction);
}

TEST(normal_response_not_exception) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
        0x01, 0x03, 0x02, 0x00, 0x0A
    };
    ASSERT_FALSE(scanner.is_exception_response(resp));
}

TEST(exception_short_response_returns_false) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {0x00, 0x01, 0x00};
    ASSERT_FALSE(scanner.is_exception_response(resp));
}

TEST(exception_code_short_response_defaults) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {0x00, 0x01};
    auto code = scanner.get_exception_code(resp);
    ASSERT_EQ(code, ExceptionCode::SlaveDeviceFailure);
}

// ===========================================================================
// Register data extraction from response bytes
// ===========================================================================

TEST(parse_register_single_value) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
        0x01, 0x03, 0x02,
        0x01, 0x23
    };
    auto regs = scanner.parse_register_response(resp);
    ASSERT_EQ(regs.size(), 1u);
    ASSERT_EQ(regs[0], 0x0123);
}

TEST(parse_register_multiple_values) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x09,
        0x01, 0x03, 0x06,
        0x00, 0x0A,
        0x00, 0xFF,
        0xAB, 0xCD
    };
    auto regs = scanner.parse_register_response(resp);
    ASSERT_EQ(regs.size(), 3u);
    ASSERT_EQ(regs[0], 10);
    ASSERT_EQ(regs[1], 255);
    ASSERT_EQ(regs[2], 0xABCD);
}

TEST(parse_register_exception_returns_empty) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
        0x01, 0x83, 0x02
    };
    auto regs = scanner.parse_register_response(resp);
    ASSERT_TRUE(regs.empty());
}

TEST(parse_register_short_response_returns_empty) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {0x00, 0x01, 0x00, 0x00};
    auto regs = scanner.parse_register_response(resp);
    ASSERT_TRUE(regs.empty());
}

TEST(parse_register_truncated_data_returns_empty) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x07,
        0x01, 0x03, 0x04,
        0x00, 0x0A
    };
    auto regs = scanner.parse_register_response(resp);
    ASSERT_TRUE(regs.empty());
}

TEST(parse_register_fc04_same_format) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
        0x01, 0x04, 0x02,
        0xFF, 0xFE
    };
    auto regs = scanner.parse_register_response(resp);
    ASSERT_EQ(regs.size(), 1u);
    ASSERT_EQ(regs[0], 0xFFFE);
}

TEST(parse_register_zero_values) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x07,
        0x01, 0x03, 0x04,
        0x00, 0x00,
        0x00, 0x00
    };
    auto regs = scanner.parse_register_response(resp);
    ASSERT_EQ(regs.size(), 2u);
    ASSERT_EQ(regs[0], 0);
    ASSERT_EQ(regs[1], 0);
}

TEST(parse_register_max_value) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
        0x01, 0x03, 0x02,
        0xFF, 0xFF
    };
    auto regs = scanner.parse_register_response(resp);
    ASSERT_EQ(regs.size(), 1u);
    ASSERT_EQ(regs[0], 0xFFFF);
}

// ===========================================================================
// Coil response parsing
// ===========================================================================

TEST(parse_coil_response_basic) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x04,
        0x01, 0x01, 0x01,
        0xCD
    };
    auto coils = scanner.parse_coil_response(resp, 8);
    ASSERT_EQ(coils.size(), 8u);
    ASSERT_TRUE(coils[0]);
    ASSERT_FALSE(coils[1]);
    ASSERT_TRUE(coils[2]);
    ASSERT_TRUE(coils[3]);
    ASSERT_FALSE(coils[4]);
    ASSERT_FALSE(coils[5]);
    ASSERT_TRUE(coils[6]);
    ASSERT_TRUE(coils[7]);
}

TEST(parse_coil_response_partial_byte) {
    auto scanner = make_scanner();
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x04,
        0x01, 0x01, 0x01,
        0x05
    };
    auto coils = scanner.parse_coil_response(resp, 3);
    ASSERT_EQ(coils.size(), 3u);
    ASSERT_TRUE(coils[0]);
    ASSERT_FALSE(coils[1]);
    ASSERT_TRUE(coils[2]);
}

// ===========================================================================
// Device ID response parsing
// ===========================================================================

TEST(parse_device_id_response_basic) {
    auto scanner = make_scanner();
    // Simulate a TCP response with FC43/14 data
    // MBAP(7) + FC(0x2B) + MEI(0x0E) + DevIdCode(0x01) + ConformityLevel(0x01)
    //         + MoreFollows(0x00) + NextObjId(0x00) + NumObjects(2)
    //         + Obj0: id=0x00 len=6 "Vendor"
    //         + Obj1: id=0x01 len=4 "Prod"
    std::vector<uint8_t> resp = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x1B,  // MBAP
        0x01,                                    // unit ID
        0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x02,  // FC43 response header
        0x00, 0x06, 'V', 'e', 'n', 'd', 'o', 'r',  // Object 0: VendorName
        0x01, 0x04, 'P', 'r', 'o', 'd',             // Object 1: ProductCode
    };
    auto id = scanner.parse_device_id_response(resp);
    ASSERT_TRUE(id.supported);
    ASSERT_EQ(id.vendor_name, "Vendor");
    ASSERT_EQ(id.product_code, "Prod");
}

// ===========================================================================
// Timeout / empty response handling
// ===========================================================================

TEST(send_receive_returns_empty_when_not_connected) {
    auto scanner = make_scanner();
    std::vector<uint8_t> request = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                                     0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    auto resp = scanner.send_receive(request);
    ASSERT_TRUE(resp.empty());
}

TEST(empty_response_means_no_registers) {
    auto scanner = make_scanner();
    std::vector<uint8_t> empty_resp;
    auto regs = scanner.parse_register_response(empty_resp);
    ASSERT_TRUE(regs.empty());
}

TEST(empty_response_means_no_coils) {
    auto scanner = make_scanner();
    std::vector<uint8_t> empty_resp;
    auto coils = scanner.parse_coil_response(empty_resp, 16);
    ASSERT_TRUE(coils.empty());
}

TEST(next_transaction_id_wraps) {
    auto scanner = make_scanner();
    scanner.transaction_counter_ = 0xFFFE;
    uint16_t id1 = scanner.next_transaction_id();
    ASSERT_EQ(id1, 0xFFFF);
    uint16_t id2 = scanner.next_transaction_id();
    ASSERT_EQ(id2, 0x0000);
}

// ===========================================================================
// Register range parsing
// ===========================================================================

TEST(parse_register_ranges_single) {
    auto ranges = parse_register_ranges("100");
    ASSERT_EQ(ranges.size(), 1u);
    ASSERT_EQ(ranges[0].start, 100);
    ASSERT_EQ(ranges[0].count, 1);
}

TEST(parse_register_ranges_range) {
    auto ranges = parse_register_ranges("0-99");
    ASSERT_EQ(ranges.size(), 1u);
    ASSERT_EQ(ranges[0].start, 0);
    ASSERT_EQ(ranges[0].count, 100);
}

TEST(parse_register_ranges_multiple) {
    auto ranges = parse_register_ranges("0-99,400-499");
    ASSERT_EQ(ranges.size(), 2u);
    ASSERT_EQ(ranges[0].start, 0);
    ASSERT_EQ(ranges[0].count, 100);
    ASSERT_EQ(ranges[1].start, 400);
    ASSERT_EQ(ranges[1].count, 100);
}

// ===========================================================================
// Finding classification
// ===========================================================================

TEST(classify_findings_critical_write) {
    auto scanner = make_scanner();
    UnitResult r{};
    r.unit_id = 1;
    r.responsive = true;
    r.holding_registers_readable = false;
    r.input_registers_readable = false;
    r.coils_readable = false;
    r.write_test_performed = true;
    r.write_test_vulnerable = true;
    r.write_test_detail = "test";

    scanner.classify_findings(r);
    ASSERT_TRUE(r.findings.size() >= 1);
    ASSERT_EQ(r.findings[0].severity, FindingSeverity::CRITICAL);
}

TEST(classify_findings_high_read) {
    auto scanner = make_scanner();
    UnitResult r{};
    r.unit_id = 1;
    r.responsive = true;
    r.holding_registers_readable = true;
    r.input_registers_readable = false;
    r.coils_readable = false;
    r.write_test_performed = false;
    r.write_test_vulnerable = false;

    scanner.classify_findings(r);
    bool has_high = false;
    for (const auto& f : r.findings) {
        if (f.severity == FindingSeverity::HIGH) has_high = true;
    }
    ASSERT_TRUE(has_high);
}
