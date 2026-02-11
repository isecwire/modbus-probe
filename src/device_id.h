#pragma once
// ---------------------------------------------------------------------------
// device_id.h -- MEI / Read Device Identification (FC43/14)
//
// Extracts vendor name, product code, revision, vendor URL, product name,
// model name, and user application name from Modbus devices that support
// the Read Device Identification function.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modbus_probe {

// Object IDs defined in Modbus specification
enum class DeviceObjectId : uint8_t {
    VendorName           = 0x00,
    ProductCode          = 0x01,
    MajorMinorRevision   = 0x02,
    VendorUrl            = 0x03,
    ProductName          = 0x04,
    ModelName            = 0x05,
    UserApplicationName  = 0x06,
};

// Read Device ID code
enum class ReadDeviceIdCode : uint8_t {
    BasicStream          = 0x01,  // Objects 0x00-0x02
    RegularStream        = 0x02,  // Objects 0x00-0x06
    ExtendedStream       = 0x03,  // Objects 0x00-0xFF
    IndividualAccess     = 0x04,  // Single object by ID
};

struct DeviceIdentification {
    std::string vendor_name;
    std::string product_code;
    std::string revision;
    std::string vendor_url;
    std::string product_name;
    std::string model_name;
    std::string user_application_name;
    // Additional/extended objects keyed by object ID
    std::map<uint8_t, std::string> extended_objects;
    bool supported = false;
};

class DeviceIdParser {
public:
    // Parse a FC43/14 response PDU (after MBAP header or RTU unit_id).
    // The input should start with the function code byte (0x2B).
    // Returns populated DeviceIdentification; .supported = false if parsing fails.
    static DeviceIdentification parse_response(const std::vector<uint8_t>& pdu);

    // Build the PDU portion (without MBAP or RTU framing) for a Device ID request
    static std::vector<uint8_t> build_request_pdu(uint8_t read_device_id_code,
                                                   uint8_t object_id);

    // Convert a DeviceIdentification to a human-readable summary
    static std::string format_summary(const DeviceIdentification& id);

    // Return the standard name for an object ID
    static std::string object_id_name(uint8_t oid);
};

}  // namespace modbus_probe
