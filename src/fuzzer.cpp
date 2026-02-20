#include "fuzzer.h"

namespace modbus_probe {

std::string FunctionCodeFuzzer::fc_name(uint8_t fc) {
    switch (fc) {
        case 0x01: return "Read Coils";
        case 0x02: return "Read Discrete Inputs";
        case 0x03: return "Read Holding Registers";
        case 0x04: return "Read Input Registers";
        case 0x05: return "Write Single Coil";
        case 0x06: return "Write Single Register";
        case 0x07: return "Read Exception Status";
        case 0x08: return "Diagnostics";
        case 0x0B: return "Get Comm Event Counter";
        case 0x0C: return "Get Comm Event Log";
        case 0x0F: return "Write Multiple Coils";
        case 0x10: return "Write Multiple Registers";
        case 0x11: return "Report Server ID";
        case 0x14: return "Read File Record";
        case 0x15: return "Write File Record";
        case 0x16: return "Mask Write Register";
        case 0x17: return "Read/Write Multiple Registers";
        case 0x18: return "Read FIFO Queue";
        case 0x2B: return "Encapsulated Interface Transport (MEI)";
        default: {
            if (fc >= 0x41 && fc <= 0x48)
                return "User-Defined FC";
            if (fc >= 0x64 && fc <= 0x6E)
                return "User-Defined FC";
            return "Unknown/Vendor-Specific FC";
        }
    }
}

std::string FunctionCodeFuzzer::exception_name(uint8_t ec) {
    switch (ec) {
        case 0x01: return "Illegal Function";
        case 0x02: return "Illegal Data Address";
        case 0x03: return "Illegal Data Value";
        case 0x04: return "Server Device Failure";
        case 0x05: return "Acknowledge";
        case 0x06: return "Server Device Busy";
        case 0x08: return "Memory Parity Error";
        case 0x0A: return "Gateway Path Unavailable";
        case 0x0B: return "Gateway Target Device Failed to Respond";
        default:   return "Unknown Exception";
    }
}

std::string FunctionCodeFuzzer::result_type_str(FuzzResultType rt) {
    switch (rt) {
        case FuzzResultType::Supported:  return "SUPPORTED";
        case FuzzResultType::Exception:  return "EXCEPTION";
        case FuzzResultType::Timeout:    return "TIMEOUT";
        case FuzzResultType::Error:      return "ERROR";
    }
    return "UNKNOWN";
}

}  // namespace modbus_probe
