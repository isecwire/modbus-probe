// Unit tests for network discovery (CIDR parsing, IP conversion)

#include "discovery.h"

#define TEST_FRAMEWORK_NO_MAIN
#include "main_test.cpp"

using namespace modbus_probe;

// ===========================================================================
// CIDR expansion
// ===========================================================================

// We test expand_cidr via the public interface indirectly;
// since it's a private static, we use a thin wrapper approach:
// The tests below verify the DiscoveryConfig and result behavior.

// Helper: access expand_cidr via a subclass for testing
class TestableDiscovery : public NetworkDiscovery {
public:
    using NetworkDiscovery::NetworkDiscovery;

    // Expose the private static methods for testing
    static std::vector<std::string> test_expand_cidr(const std::string& cidr) {
        return expand_cidr(cidr);
    }

    static uint32_t test_parse_ipv4(const std::string& ip) {
        return parse_ipv4(ip);
    }

    static std::string test_ipv4_to_string(uint32_t ip) {
        return ipv4_to_string(ip);
    }
};

TEST(parse_ipv4_loopback) {
    uint32_t ip = TestableDiscovery::test_parse_ipv4("127.0.0.1");
    ASSERT_EQ(ip, 0x7F000001u);
}

TEST(parse_ipv4_private) {
    uint32_t ip = TestableDiscovery::test_parse_ipv4("192.168.1.100");
    ASSERT_EQ(ip, 0xC0A80164u);
}

TEST(ipv4_to_string_roundtrip) {
    std::string orig = "10.0.0.50";
    uint32_t ip = TestableDiscovery::test_parse_ipv4(orig);
    std::string result = TestableDiscovery::test_ipv4_to_string(ip);
    ASSERT_EQ(result, orig);
}

TEST(expand_cidr_single_ip) {
    auto ips = TestableDiscovery::test_expand_cidr("192.168.1.100");
    ASSERT_EQ(ips.size(), 1u);
    ASSERT_EQ(ips[0], "192.168.1.100");
}

TEST(expand_cidr_slash_32) {
    auto ips = TestableDiscovery::test_expand_cidr("10.0.0.1/32");
    ASSERT_EQ(ips.size(), 1u);
    ASSERT_EQ(ips[0], "10.0.0.1");
}

TEST(expand_cidr_slash_30) {
    // /30 = 4 addresses, minus network and broadcast = 2 hosts
    auto ips = TestableDiscovery::test_expand_cidr("192.168.1.0/30");
    ASSERT_EQ(ips.size(), 2u);
    ASSERT_EQ(ips[0], "192.168.1.1");
    ASSERT_EQ(ips[1], "192.168.1.2");
}

TEST(expand_cidr_slash_24) {
    auto ips = TestableDiscovery::test_expand_cidr("10.0.0.0/24");
    // /24 = 256 addresses, minus network (10.0.0.0) and broadcast (10.0.0.255) = 254
    ASSERT_EQ(ips.size(), 254u);
    ASSERT_EQ(ips[0], "10.0.0.1");
    ASSERT_EQ(ips[253], "10.0.0.254");
}

TEST(expand_cidr_slash_31) {
    // /31 point-to-point: both addresses included
    auto ips = TestableDiscovery::test_expand_cidr("10.0.0.0/31");
    ASSERT_EQ(ips.size(), 2u);
    ASSERT_EQ(ips[0], "10.0.0.0");
    ASSERT_EQ(ips[1], "10.0.0.1");
}

TEST(expand_cidr_invalid_prefix) {
    auto ips = TestableDiscovery::test_expand_cidr("10.0.0.0/33");
    ASSERT_EQ(ips.size(), 0u);
}

TEST(discovery_config_defaults) {
    DiscoveryConfig config;
    ASSERT_EQ(config.port, 502);
    ASSERT_EQ(config.timeout_ms, 500);
    ASSERT_EQ(config.thread_count, 16);
    ASSERT_TRUE(config.probe_modbus);
}
