// Unit tests for Device Identification (FC43/14) parser

#include "device_id.h"

#define TEST_FRAMEWORK_NO_MAIN
#include "main_test.cpp"

using namespace modbus_probe;

// ===========================================================================
// PDU building
// ===========================================================================

TEST(device_id_build_request_pdu) {
    auto pdu = DeviceIdParser::build_request_pdu(0x01, 0x00);
    ASSERT_EQ(pdu.size(), 4u);
    ASSERT_EQ(pdu[0], 0x2B);  // FC43
    ASSERT_EQ(pdu[1], 0x0E);  // MEI type
    ASSERT_EQ(pdu[2], 0x01);  // ReadDeviceIdCode
    ASSERT_EQ(pdu[3], 0x00);  // ObjectId
}

// ===========================================================================
// Response parsing
// ===========================================================================

TEST(device_id_parse_basic_response) {
    // FC43 response with VendorName and ProductCode
    std::vector<uint8_t> pdu = {
        0x2B, 0x0E,  // FC + MEI type
        0x01,        // ReadDeviceIdCode echo
        0x01,        // Conformity level
        0x00,        // More follows: no
        0x00,        // Next object ID
        0x02,        // Number of objects
        // Object 0: VendorName = "ACME"
        0x00, 0x04, 'A', 'C', 'M', 'E',
        // Object 1: ProductCode = "PLC-100"
        0x01, 0x07, 'P', 'L', 'C', '-', '1', '0', '0',
    };

    auto id = DeviceIdParser::parse_response(pdu);
    ASSERT_TRUE(id.supported);
    ASSERT_EQ(id.vendor_name, "ACME");
    ASSERT_EQ(id.product_code, "PLC-100");
}

TEST(device_id_parse_full_response) {
    std::vector<uint8_t> pdu = {
        0x2B, 0x0E, 0x02, 0x02, 0x00, 0x00, 0x03,
        // VendorName
        0x00, 0x07, 'S', 'i', 'e', 'm', 'e', 'n', 's',
        // ProductCode
        0x01, 0x06, 'S', '7', '-', '3', '0', '0',
        // Revision
        0x02, 0x05, '3', '.', '2', '.', '1',
    };

    auto id = DeviceIdParser::parse_response(pdu);
    ASSERT_TRUE(id.supported);
    ASSERT_EQ(id.vendor_name, "Siemens");
    ASSERT_EQ(id.product_code, "S7-300");
    ASSERT_EQ(id.revision, "3.2.1");
}

TEST(device_id_parse_empty_pdu) {
    std::vector<uint8_t> pdu;
    auto id = DeviceIdParser::parse_response(pdu);
    ASSERT_FALSE(id.supported);
}

TEST(device_id_parse_wrong_fc) {
    std::vector<uint8_t> pdu = {0x03, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x00};
    auto id = DeviceIdParser::parse_response(pdu);
    ASSERT_FALSE(id.supported);
}

TEST(device_id_parse_truncated_object) {
    // Claims 1 object but data is truncated
    std::vector<uint8_t> pdu = {
        0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x10  // Object claims 16 bytes but none follow
    };
    auto id = DeviceIdParser::parse_response(pdu);
    // Should still parse but with empty vendor name
    ASSERT_TRUE(id.supported);
    ASSERT_TRUE(id.vendor_name.empty());
}

TEST(device_id_parse_extended_objects) {
    std::vector<uint8_t> pdu = {
        0x2B, 0x0E, 0x03, 0x03, 0x00, 0x00, 0x01,
        // Extended object ID 0x80
        0x80, 0x05, 'H', 'e', 'l', 'l', 'o',
    };

    auto id = DeviceIdParser::parse_response(pdu);
    ASSERT_TRUE(id.supported);
    ASSERT_EQ(id.extended_objects.size(), 1u);
    ASSERT_EQ(id.extended_objects[0x80], "Hello");
}

// ===========================================================================
// Object ID naming
// ===========================================================================

TEST(object_id_name_standard) {
    ASSERT_EQ(DeviceIdParser::object_id_name(0x00), "VendorName");
    ASSERT_EQ(DeviceIdParser::object_id_name(0x01), "ProductCode");
    ASSERT_EQ(DeviceIdParser::object_id_name(0x02), "MajorMinorRevision");
}

TEST(object_id_name_unknown) {
    auto name = DeviceIdParser::object_id_name(0x80);
    ASSERT_STR_CONTAINS(name, "0x80");
}

// ===========================================================================
// Summary formatting
// ===========================================================================

TEST(device_id_format_summary_supported) {
    DeviceIdentification id;
    id.supported = true;
    id.vendor_name = "ACME";
    id.product_code = "PLC-100";
    id.revision = "1.0";
    auto summary = DeviceIdParser::format_summary(id);
    ASSERT_STR_CONTAINS(summary, "ACME");
    ASSERT_STR_CONTAINS(summary, "PLC-100");
    ASSERT_STR_CONTAINS(summary, "1.0");
}

TEST(device_id_format_summary_not_supported) {
    DeviceIdentification id;
    id.supported = false;
    auto summary = DeviceIdParser::format_summary(id);
    ASSERT_STR_CONTAINS(summary, "not supported");
}
