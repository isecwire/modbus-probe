#include "pcap_writer.h"

#include <chrono>
#include <cstring>

namespace modbus_probe {

PcapWriter::~PcapWriter() {
    close();
}

bool PcapWriter::open(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) file_.close();

    file_.open(path, std::ios::binary | std::ios::trunc);
    if (!file_.is_open()) return false;

    // Write the global PCAP header
    PcapGlobalHeader gh;
    file_.write(reinterpret_cast<const char*>(&gh.magic_number),  4);
    file_.write(reinterpret_cast<const char*>(&gh.version_major), 2);
    file_.write(reinterpret_cast<const char*>(&gh.version_minor), 2);
    file_.write(reinterpret_cast<const char*>(&gh.thiszone),      4);
    file_.write(reinterpret_cast<const char*>(&gh.sigfigs),       4);
    file_.write(reinterpret_cast<const char*>(&gh.snaplen),       4);
    file_.write(reinterpret_cast<const char*>(&gh.network),       4);

    packet_count_ = 0;
    seq_client_ = 1000;
    seq_server_ = 2000;

    return file_.good();
}

void PcapWriter::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }
}

bool PcapWriter::write_packet(uint32_t src_ip, uint16_t src_port,
                               uint32_t dst_ip, uint16_t dst_port,
                               const std::vector<uint8_t>& payload,
                               PacketDirection dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!file_.is_open()) return false;

    // Choose seq/ack based on direction
    uint32_t seq, ack;
    if (dir == PacketDirection::Request) {
        seq = seq_client_;
        ack = seq_server_;
        seq_client_ += static_cast<uint32_t>(payload.size());
    } else {
        seq = seq_server_;
        ack = seq_client_;
        seq_server_ += static_cast<uint32_t>(payload.size());
    }

    // Build TCP header (20 bytes)
    auto tcp_hdr = build_tcp_header(src_port, dst_port, seq, ack,
                                     static_cast<uint16_t>(payload.size()));

    // Total IP payload = TCP header + Modbus payload
    uint16_t ip_total_len = static_cast<uint16_t>(20 + tcp_hdr.size() + payload.size());

    // Build IPv4 header (20 bytes)
    auto ip_hdr = build_ipv4_header(src_ip, dst_ip, ip_total_len);

    // Assemble full packet
    std::vector<uint8_t> packet;
    packet.reserve(ip_hdr.size() + tcp_hdr.size() + payload.size());
    packet.insert(packet.end(), ip_hdr.begin(), ip_hdr.end());
    packet.insert(packet.end(), tcp_hdr.begin(), tcp_hdr.end());
    packet.insert(packet.end(), payload.begin(), payload.end());

    // Write PCAP packet header
    uint32_t ts_sec, ts_usec;
    get_timestamp(ts_sec, ts_usec);

    PcapPacketHeader ph;
    ph.ts_sec   = ts_sec;
    ph.ts_usec  = ts_usec;
    ph.incl_len = static_cast<uint32_t>(packet.size());
    ph.orig_len = static_cast<uint32_t>(packet.size());

    file_.write(reinterpret_cast<const char*>(&ph.ts_sec),   4);
    file_.write(reinterpret_cast<const char*>(&ph.ts_usec),  4);
    file_.write(reinterpret_cast<const char*>(&ph.incl_len), 4);
    file_.write(reinterpret_cast<const char*>(&ph.orig_len), 4);

    // Write packet data
    file_.write(reinterpret_cast<const char*>(packet.data()),
                static_cast<std::streamsize>(packet.size()));

    ++packet_count_;
    return file_.good();
}

bool PcapWriter::write_raw(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!file_.is_open()) return false;

    uint32_t ts_sec, ts_usec;
    get_timestamp(ts_sec, ts_usec);

    PcapPacketHeader ph;
    ph.ts_sec   = ts_sec;
    ph.ts_usec  = ts_usec;
    ph.incl_len = static_cast<uint32_t>(data.size());
    ph.orig_len = static_cast<uint32_t>(data.size());

    file_.write(reinterpret_cast<const char*>(&ph.ts_sec),   4);
    file_.write(reinterpret_cast<const char*>(&ph.ts_usec),  4);
    file_.write(reinterpret_cast<const char*>(&ph.incl_len), 4);
    file_.write(reinterpret_cast<const char*>(&ph.orig_len), 4);
    file_.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));

    ++packet_count_;
    return file_.good();
}

// ---------------------------------------------------------------------------
// IPv4 header (20 bytes, no options)
// ---------------------------------------------------------------------------
std::vector<uint8_t> PcapWriter::build_ipv4_header(uint32_t src_ip, uint32_t dst_ip,
                                                     uint16_t total_length) const {
    std::vector<uint8_t> hdr(20, 0);

    hdr[0] = 0x45;  // version=4, IHL=5 (20 bytes)
    hdr[1] = 0x00;  // DSCP/ECN
    hdr[2] = static_cast<uint8_t>(total_length >> 8);
    hdr[3] = static_cast<uint8_t>(total_length & 0xFF);
    // Identification (bytes 4-5): leave 0
    // Flags + Fragment offset (bytes 6-7): 0x4000 = Don't Fragment
    hdr[6] = 0x40;
    hdr[7] = 0x00;
    hdr[8] = 64;    // TTL
    hdr[9] = 6;     // Protocol: TCP

    // Source IP (network byte order = big-endian)
    hdr[12] = static_cast<uint8_t>((src_ip >> 24) & 0xFF);
    hdr[13] = static_cast<uint8_t>((src_ip >> 16) & 0xFF);
    hdr[14] = static_cast<uint8_t>((src_ip >>  8) & 0xFF);
    hdr[15] = static_cast<uint8_t>( src_ip        & 0xFF);

    // Destination IP
    hdr[16] = static_cast<uint8_t>((dst_ip >> 24) & 0xFF);
    hdr[17] = static_cast<uint8_t>((dst_ip >> 16) & 0xFF);
    hdr[18] = static_cast<uint8_t>((dst_ip >>  8) & 0xFF);
    hdr[19] = static_cast<uint8_t>( dst_ip        & 0xFF);

    // Compute header checksum (bytes 10-11)
    uint16_t cksum = ip_checksum(hdr.data(), 20);
    hdr[10] = static_cast<uint8_t>(cksum >> 8);
    hdr[11] = static_cast<uint8_t>(cksum & 0xFF);

    return hdr;
}

// ---------------------------------------------------------------------------
// TCP header (20 bytes, no options)
// ---------------------------------------------------------------------------
std::vector<uint8_t> PcapWriter::build_tcp_header(uint16_t src_port, uint16_t dst_port,
                                                    uint32_t seq, uint32_t ack,
                                                    uint16_t /*payload_len*/) const {
    std::vector<uint8_t> hdr(20, 0);

    // Source port
    hdr[0] = static_cast<uint8_t>(src_port >> 8);
    hdr[1] = static_cast<uint8_t>(src_port & 0xFF);

    // Destination port
    hdr[2] = static_cast<uint8_t>(dst_port >> 8);
    hdr[3] = static_cast<uint8_t>(dst_port & 0xFF);

    // Sequence number
    hdr[4] = static_cast<uint8_t>(seq >> 24);
    hdr[5] = static_cast<uint8_t>(seq >> 16);
    hdr[6] = static_cast<uint8_t>(seq >>  8);
    hdr[7] = static_cast<uint8_t>(seq);

    // Acknowledgment number
    hdr[8]  = static_cast<uint8_t>(ack >> 24);
    hdr[9]  = static_cast<uint8_t>(ack >> 16);
    hdr[10] = static_cast<uint8_t>(ack >>  8);
    hdr[11] = static_cast<uint8_t>(ack);

    // Data offset (5 words = 20 bytes) + flags (ACK+PSH)
    hdr[12] = 0x50;  // data offset = 5
    hdr[13] = 0x18;  // ACK + PSH

    // Window size
    hdr[14] = 0xFF;
    hdr[15] = 0xFF;

    // Checksum left as 0 (sufficient for pcap analysis)
    // Urgent pointer left as 0

    return hdr;
}

void PcapWriter::get_timestamp(uint32_t& sec, uint32_t& usec) {
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(epoch);
    auto usecs = std::chrono::duration_cast<std::chrono::microseconds>(epoch) -
                 std::chrono::duration_cast<std::chrono::microseconds>(secs);
    sec  = static_cast<uint32_t>(secs.count());
    usec = static_cast<uint32_t>(usecs.count());
}

uint16_t PcapWriter::ip_checksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < length; i += 2) {
        sum += (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
    }
    if (length & 1) {
        sum += static_cast<uint16_t>(data[length - 1]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

}  // namespace modbus_probe
