#include "device_id.h"

#include <sstream>

namespace modbus_probe {

std::string DeviceIdParser::object_id_name(uint8_t oid) {
    switch (oid) {
        case 0x00: return "VendorName";
        case 0x01: return "ProductCode";
        case 0x02: return "MajorMinorRevision";
        case 0x03: return "VendorUrl";
        case 0x04: return "ProductName";
        case 0x05: return "ModelName";
        case 0x06: return "UserApplicationName";
        default: {
            std::ostringstream os;
            os << "Object_0x" << std::hex << static_cast<int>(oid);
            return os.str();
        }
    }
}

std::vector<uint8_t> DeviceIdParser::build_request_pdu(uint8_t read_device_id_code,
                                                        uint8_t object_id) {
    // FC43 (0x2B) + MEI type 0x0E + read_device_id_code + object_id
    return {0x2B, 0x0E, read_device_id_code, object_id};
}

DeviceIdentification DeviceIdParser::parse_response(const std::vector<uint8_t>& pdu) {
    DeviceIdentification result;
    result.supported = false;

    // Minimum response: FC(1) + MEI(1) + DevIdCode(1) + ConformityLevel(1)
    //                   + MoreFollows(1) + NextObjId(1) + NumObjects(1) = 7
    if (pdu.size() < 7) return result;

    // Verify FC43 / MEI 0x0E
    if (pdu[0] != 0x2B || pdu[1] != 0x0E) return result;

    // Check for exception (bit 7 set)
    if (pdu[0] & 0x80) return result;

    // pdu[2] = read_device_id_code (echo)
    // pdu[3] = conformity level
    // pdu[4] = more_follows (0x00 = no, 0xFF = yes)
    // pdu[5] = next_object_id
    uint8_t num_objects = pdu[6];

    size_t offset = 7;
    for (uint8_t i = 0; i < num_objects; ++i) {
        if (offset + 2 > pdu.size()) break;

        uint8_t obj_id = pdu[offset];
        uint8_t obj_len = pdu[offset + 1];
        offset += 2;

        if (offset + obj_len > pdu.size()) break;

        std::string value(reinterpret_cast<const char*>(&pdu[offset]), obj_len);
        offset += obj_len;

        switch (obj_id) {
            case 0x00: result.vendor_name = value; break;
            case 0x01: result.product_code = value; break;
            case 0x02: result.revision = value; break;
            case 0x03: result.vendor_url = value; break;
            case 0x04: result.product_name = value; break;
            case 0x05: result.model_name = value; break;
            case 0x06: result.user_application_name = value; break;
            default:   result.extended_objects[obj_id] = value; break;
        }
    }

    result.supported = true;
    return result;
}

std::string DeviceIdParser::format_summary(const DeviceIdentification& id) {
    if (!id.supported) return "(Device ID not supported)";

    std::ostringstream os;
    if (!id.vendor_name.empty())
        os << "Vendor: " << id.vendor_name << "\n";
    if (!id.product_code.empty())
        os << "Product Code: " << id.product_code << "\n";
    if (!id.revision.empty())
        os << "Revision: " << id.revision << "\n";
    if (!id.vendor_url.empty())
        os << "Vendor URL: " << id.vendor_url << "\n";
    if (!id.product_name.empty())
        os << "Product Name: " << id.product_name << "\n";
    if (!id.model_name.empty())
        os << "Model Name: " << id.model_name << "\n";
    if (!id.user_application_name.empty())
        os << "User App: " << id.user_application_name << "\n";

    for (const auto& [oid, val] : id.extended_objects) {
        os << object_id_name(oid) << ": " << val << "\n";
    }

    return os.str();
}

}  // namespace modbus_probe
