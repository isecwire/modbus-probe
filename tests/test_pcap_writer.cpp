// Unit tests for PCAP writer

#include "pcap_writer.h"

#include <cstdio>
#include <fstream>

#define TEST_FRAMEWORK_NO_MAIN
#include "main_test.cpp"

using namespace modbus_probe;

// ===========================================================================
// PCAP global header
// ===========================================================================

TEST(pcap_open_creates_file) {
    const char* path = "/tmp/modbus_probe_test.pcap";
    PcapWriter writer;
    ASSERT_TRUE(writer.open(path));
    ASSERT_TRUE(writer.is_open());
    writer.close();
    ASSERT_FALSE(writer.is_open());

    // Verify file exists and has at least the 24-byte global header
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    ASSERT_TRUE(f.is_open());
    auto size = f.tellg();
    ASSERT_GE(static_cast<int>(size), 24);

    std::remove(path);
}

TEST(pcap_global_header_magic) {
    const char* path = "/tmp/modbus_probe_test_magic.pcap";
    PcapWriter writer;
    writer.open(path);
    writer.close();

    std::ifstream f(path, std::ios::binary);
    uint32_t magic = 0;
    f.read(reinterpret_cast<char*>(&magic), 4);
    ASSERT_EQ(magic, PCAP_MAGIC);

    std::remove(path);
}

TEST(pcap_global_header_linktype) {
    const char* path = "/tmp/modbus_probe_test_link.pcap";
    PcapWriter writer;
    writer.open(path);
    writer.close();

    std::ifstream f(path, std::ios::binary);
    // Skip to network field (offset 20)
    f.seekg(20);
    uint32_t linktype = 0;
    f.read(reinterpret_cast<char*>(&linktype), 4);
    ASSERT_EQ(linktype, PCAP_LINKTYPE_RAW);

    std::remove(path);
}

// ===========================================================================
// Packet writing
// ===========================================================================

TEST(pcap_write_raw_packet) {
    const char* path = "/tmp/modbus_probe_test_raw.pcap";
    PcapWriter writer;
    writer.open(path);

    std::vector<uint8_t> data = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    ASSERT_TRUE(writer.write_raw(data));
    ASSERT_EQ(writer.packet_count(), 1u);

    writer.close();

    // File should be: global header (24) + packet header (16) + data (6) = 46
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    auto size = f.tellg();
    ASSERT_EQ(static_cast<int>(size), 46);

    std::remove(path);
}

TEST(pcap_write_modbus_packet) {
    const char* path = "/tmp/modbus_probe_test_modbus.pcap";
    PcapWriter writer;
    writer.open(path);

    // Simulate a Modbus TCP request (MBAP + FC03)
    std::vector<uint8_t> mbap_request = {
        0x00, 0x01,  // transaction ID
        0x00, 0x00,  // protocol ID
        0x00, 0x06,  // length
        0x01,        // unit ID
        0x03,        // FC03
        0x00, 0x00,  // start addr
        0x00, 0x0A,  // quantity
    };

    // src=192.168.1.10 (0xC0A8010A), dst=192.168.1.100 (0xC0A80164)
    ASSERT_TRUE(writer.write_packet(0xC0A8010A, 49152,
                                     0xC0A80164, 502,
                                     mbap_request,
                                     PacketDirection::Request));

    ASSERT_EQ(writer.packet_count(), 1u);

    // File should have: global header (24) + packet header (16) +
    //   IP header (20) + TCP header (20) + payload (12) = 92
    writer.close();
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    auto size = f.tellg();
    ASSERT_EQ(static_cast<int>(size), 92);

    std::remove(path);
}

TEST(pcap_packet_count_increments) {
    const char* path = "/tmp/modbus_probe_test_count.pcap";
    PcapWriter writer;
    writer.open(path);

    std::vector<uint8_t> data = {0xAA, 0xBB};
    writer.write_raw(data);
    writer.write_raw(data);
    writer.write_raw(data);

    ASSERT_EQ(writer.packet_count(), 3u);

    writer.close();
    std::remove(path);
}

TEST(pcap_write_fails_when_closed) {
    PcapWriter writer;
    std::vector<uint8_t> data = {0x01};
    ASSERT_FALSE(writer.write_raw(data));
}
