#pragma once
// ---------------------------------------------------------------------------
// rtu_framing.h -- Modbus RTU-over-TCP frame builder with CRC-16
//
// Modbus RTU frames use a different envelope than Modbus TCP (MBAP).  When
// tunnelled over TCP (common with serial-to-Ethernet gateways), the MBAP
// header is absent and instead each ADU carries a trailing CRC-16/Modbus.
//
// Frame layout:  [unit_id(1)] [function_code(1)] [data(N)] [CRC_lo(1)] [CRC_hi(1)]
// ---------------------------------------------------------------------------

#include <cstdint>
#include <vector>

namespace modbus_probe {

class RtuFraming {
public:
    // --- CRC-16/Modbus (polynomial 0xA001, reflected) ----------------------
    static uint16_t crc16(const uint8_t* data, size_t length);
    static uint16_t crc16(const std::vector<uint8_t>& data);

    // --- Frame builders (RTU ADU: unit + PDU + CRC) ------------------------

    // Generic read request: FC01/02/03/04
    static std::vector<uint8_t> build_read_request(uint8_t unit_id,
                                                    uint8_t function_code,
                                                    uint16_t start_addr,
                                                    uint16_t quantity);

    // FC05: Write Single Coil (value 0xFF00 = ON, 0x0000 = OFF)
    static std::vector<uint8_t> build_write_single_coil(uint8_t unit_id,
                                                         uint16_t addr,
                                                         bool value);

    // FC06: Write Single Register
    static std::vector<uint8_t> build_write_single_register(uint8_t unit_id,
                                                             uint16_t addr,
                                                             uint16_t value);

    // FC15: Write Multiple Coils
    static std::vector<uint8_t> build_write_multiple_coils(uint8_t unit_id,
                                                            uint16_t start_addr,
                                                            const std::vector<bool>& values);

    // FC16: Write Multiple Registers
    static std::vector<uint8_t> build_write_multiple_registers(uint8_t unit_id,
                                                                uint16_t start_addr,
                                                                const std::vector<uint16_t>& values);

    // FC43/14: Read Device Identification (MEI)
    static std::vector<uint8_t> build_read_device_id(uint8_t unit_id,
                                                      uint8_t read_device_id_code,
                                                      uint8_t object_id);

    // Arbitrary FC (for fuzzing) -- sends FC + optional payload
    static std::vector<uint8_t> build_raw_fc(uint8_t unit_id,
                                              uint8_t function_code,
                                              const std::vector<uint8_t>& payload = {});

    // --- Validation --------------------------------------------------------
    // Returns true if frame has valid CRC
    static bool validate_crc(const std::vector<uint8_t>& frame);

    // Strip CRC from validated frame, return PDU portion (unit_id + FC + data)
    static std::vector<uint8_t> strip_crc(const std::vector<uint8_t>& frame);

private:
    static void append_crc(std::vector<uint8_t>& frame);
};

}  // namespace modbus_probe
