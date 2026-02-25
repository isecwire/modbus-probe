#pragma once
// ---------------------------------------------------------------------------
// pcap_writer.h -- Write Modbus TCP frames to PCAP format for Wireshark
//
// Generates a standard pcap file with global header (magic, version 2.4,
// LINKTYPE_RAW=101) and per-packet records with microsecond timestamps.
// Each captured frame is written as a raw IP/TCP/Modbus payload.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

namespace modbus_probe {

// PCAP global header constants
constexpr uint32_t PCAP_MAGIC       = 0xA1B2C3D4;
constexpr uint16_t PCAP_VERSION_MAJ = 2;
constexpr uint16_t PCAP_VERSION_MIN = 4;
constexpr uint32_t PCAP_SNAPLEN     = 65535;
constexpr uint32_t PCAP_LINKTYPE_RAW = 101;  // LINKTYPE_RAW (raw IPv4/IPv6)

// PCAP global header (24 bytes)
struct PcapGlobalHeader {
    uint32_t magic_number  = PCAP_MAGIC;
    uint16_t version_major = PCAP_VERSION_MAJ;
    uint16_t version_minor = PCAP_VERSION_MIN;
    int32_t  thiszone      = 0;    // GMT correction
    uint32_t sigfigs       = 0;    // timestamp accuracy
    uint32_t snaplen       = PCAP_SNAPLEN;
    uint32_t network       = PCAP_LINKTYPE_RAW;
};

// PCAP per-packet header (16 bytes)
struct PcapPacketHeader {
    uint32_t ts_sec;       // timestamp seconds
    uint32_t ts_usec;      // timestamp microseconds
    uint32_t incl_len;     // number of bytes of packet saved in file
    uint32_t orig_len;     // actual length of packet
};

// Direction of the captured frame (for annotation)
enum class PacketDirection {
    Request,
    Response,
};

class PcapWriter {
public:
    // Open a pcap file for writing; returns false on failure
    bool open(const std::string& path);

    // Close the file (also called by destructor)
    void close();

    // Write a Modbus TCP frame (MBAP + PDU) wrapped in a minimal
    // IPv4/TCP envelope so Wireshark decodes it correctly.
    //
    //   src_ip / dst_ip   -- IPv4 addresses (host byte order)
    //   src_port / dst_port -- TCP ports
    //   payload           -- raw Modbus TCP frame (MBAP header + PDU)
    //   dir               -- request or response (used for TCP seq/ack)
    //
    // Thread-safe: internally locked.
    bool write_packet(uint32_t src_ip, uint16_t src_port,
                      uint32_t dst_ip, uint16_t dst_port,
                      const std::vector<uint8_t>& payload,
                      PacketDirection dir = PacketDirection::Request);

    // Convenience: write raw bytes without IP/TCP wrapping
    // (writes as LINKTYPE_RAW with the raw payload)
    bool write_raw(const std::vector<uint8_t>& data);

    // Returns the number of packets written so far
    uint32_t packet_count() const { return packet_count_; }

    bool is_open() const { return file_.is_open(); }

    ~PcapWriter();

private:
    // Build a minimal IPv4 header (20 bytes)
    std::vector<uint8_t> build_ipv4_header(uint32_t src_ip, uint32_t dst_ip,
                                            uint16_t total_length) const;

    // Build a minimal TCP header (20 bytes, no options)
    std::vector<uint8_t> build_tcp_header(uint16_t src_port, uint16_t dst_port,
                                           uint32_t seq, uint32_t ack,
                                           uint16_t payload_len) const;

    // Get current time as (seconds, microseconds)
    static void get_timestamp(uint32_t& sec, uint32_t& usec);

    // IP checksum
    static uint16_t ip_checksum(const uint8_t* data, size_t length);

    std::ofstream file_;
    std::mutex    mutex_;
    uint32_t      packet_count_ = 0;
    uint32_t      seq_client_   = 1000;  // simulated TCP seq numbers
    uint32_t      seq_server_   = 2000;
};

}  // namespace modbus_probe
