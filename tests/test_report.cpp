// Unit tests for ReportGenerator -- JSON output correctness

#include "report.h"

#define TEST_FRAMEWORK_NO_MAIN
#include "main_test.cpp"

using namespace modbus_probe;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static ScanReport make_empty_report() {
    ScanReport r{};
    r.target_host = "10.0.0.1";
    r.target_port = 502;
    r.scan_start = "2026-01-15T10:00:00.000Z";
    r.scan_end   = "2026-01-15T10:01:00.000Z";
    r.tool_version = "2.0.0";
    r.protocol_mode = "tcp";
    r.units_scanned = 0;
    r.units_responsive = 0;
    r.unauthenticated_reads = 0;
    r.unauthenticated_writes = 0;
    r.devices_identified = 0;
    r.thread_count = 1;
    return r;
}

static UnitResult make_unit(uint8_t id, bool responsive) {
    UnitResult u{};
    u.unit_id = id;
    u.responsive = responsive;
    u.holding_registers_readable = false;
    u.input_registers_readable = false;
    u.coils_readable = false;
    u.write_test_performed = false;
    u.write_test_vulnerable = false;
    u.device_id_supported = false;
    return u;
}

// ===========================================================================
// JSON generation correctness
// ===========================================================================

TEST(json_contains_tool_field) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"tool\": \"modbus-probe\"");
}

TEST(json_contains_version) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"version\": \"2.0.0\"");
}

TEST(json_contains_target_host) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"target_host\": \"10.0.0.1\"");
}

TEST(json_contains_target_port) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"target_port\": 502");
}

TEST(json_contains_protocol_mode) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"protocol_mode\": \"tcp\"");
}

TEST(json_contains_timestamps) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"scan_start\": \"2026-01-15T10:00:00.000Z\"");
    ASSERT_STR_CONTAINS(json, "\"scan_end\": \"2026-01-15T10:01:00.000Z\"");
}

TEST(json_contains_summary_block) {
    auto report = make_empty_report();
    report.units_scanned = 247;
    report.units_responsive = 3;
    report.unauthenticated_reads = 2;
    report.unauthenticated_writes = 1;
    report.devices_identified = 1;
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"units_scanned\": 247");
    ASSERT_STR_CONTAINS(json, "\"units_responsive\": 3");
    ASSERT_STR_CONTAINS(json, "\"unauthenticated_reads\": 2");
    ASSERT_STR_CONTAINS(json, "\"unauthenticated_writes\": 1");
    ASSERT_STR_CONTAINS(json, "\"devices_identified\": 1");
}

TEST(json_contains_thread_count) {
    auto report = make_empty_report();
    report.thread_count = 4;
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"thread_count\": 4");
}

TEST(json_starts_with_brace) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_TRUE(json.size() > 0);
    ASSERT_EQ(json[0], '{');
}

TEST(json_ends_with_brace_newline) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_TRUE(json.size() >= 2);
    ASSERT_EQ(json[json.size() - 2], '}');
    ASSERT_EQ(json[json.size() - 1], '\n');
}

// ===========================================================================
// String escaping in JSON output
// ===========================================================================

TEST(json_escapes_quotes_in_host) {
    auto report = make_empty_report();
    report.target_host = "host\"with\"quotes";
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "host\\\"with\\\"quotes");
}

TEST(json_escapes_backslash) {
    auto report = make_empty_report();
    report.target_host = "path\\to\\host";
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "path\\\\to\\\\host");
}

TEST(json_escapes_newline_in_detail) {
    auto report = make_empty_report();
    auto unit = make_unit(1, true);
    unit.write_test_performed = true;
    unit.write_test_detail = "line1\nline2";
    report.results.push_back(unit);
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "line1\\nline2");
}

TEST(json_escapes_tab) {
    auto report = make_empty_report();
    auto unit = make_unit(1, true);
    unit.error = "error\there";
    report.results.push_back(unit);
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "error\\there");
}

TEST(json_escapes_control_chars) {
    auto report = make_empty_report();
    report.target_host = std::string("host") + '\x01' + "end";
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\\u0001");
}

// ===========================================================================
// Empty report handling
// ===========================================================================

TEST(empty_report_has_empty_results_array) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"results\": [");
    ASSERT_TRUE(json.find("\"unit_id\"") == std::string::npos);
}

TEST(empty_report_summary_zeros) {
    auto report = make_empty_report();
    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"units_scanned\": 0");
    ASSERT_STR_CONTAINS(json, "\"units_responsive\": 0");
    ASSERT_STR_CONTAINS(json, "\"unauthenticated_reads\": 0");
    ASSERT_STR_CONTAINS(json, "\"unauthenticated_writes\": 0");
}

// ===========================================================================
// Report with multiple units
// ===========================================================================

TEST(report_single_unit_with_registers) {
    auto report = make_empty_report();
    auto unit = make_unit(1, true);
    unit.holding_registers_readable = true;
    unit.holding_registers.push_back({0, 100});
    unit.holding_registers.push_back({1, 200});
    report.results.push_back(unit);
    report.units_responsive = 1;

    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"unit_id\": 1");
    ASSERT_STR_CONTAINS(json, "\"readable\": true");
    ASSERT_STR_CONTAINS(json, "\"address\": 0, \"value\": 100");
    ASSERT_STR_CONTAINS(json, "\"address\": 1, \"value\": 200");
}

TEST(report_multiple_units) {
    auto report = make_empty_report();
    auto u1 = make_unit(1, true);
    u1.holding_registers_readable = true;
    auto u2 = make_unit(5, true);
    u2.coils_readable = true;
    u2.coils.push_back({0, true});
    u2.coils.push_back({1, false});
    report.results.push_back(u1);
    report.results.push_back(u2);
    report.units_responsive = 2;

    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"unit_id\": 1");
    ASSERT_STR_CONTAINS(json, "\"unit_id\": 5");
    ASSERT_STR_CONTAINS(json, "\"value\": true");
    ASSERT_STR_CONTAINS(json, "\"value\": false");
}

TEST(report_nonresponsive_units_excluded) {
    auto report = make_empty_report();
    auto u1 = make_unit(1, false);
    auto u2 = make_unit(2, true);
    report.results.push_back(u1);
    report.results.push_back(u2);

    auto json = ReportGenerator::to_json(report);
    ASSERT_TRUE(json.find("\"unit_id\": 1") == std::string::npos);
    ASSERT_STR_CONTAINS(json, "\"unit_id\": 2");
}

TEST(report_write_test_details) {
    auto report = make_empty_report();
    auto unit = make_unit(3, true);
    unit.write_test_performed = true;
    unit.write_test_vulnerable = true;
    unit.write_test_detail = "Unauthorized write succeeded and was rolled back (addr=0)";
    report.results.push_back(unit);

    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"performed\": true");
    ASSERT_STR_CONTAINS(json, "\"vulnerable\": true");
    ASSERT_STR_CONTAINS(json, "Unauthorized write succeeded");
}

TEST(report_unit_with_error_field) {
    auto report = make_empty_report();
    auto unit = make_unit(10, true);
    unit.error = "Connection reset during read";
    report.results.push_back(unit);

    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"error\": \"Connection reset during read\"");
}

// ===========================================================================
// Device identification in JSON
// ===========================================================================

TEST(report_device_id_in_json) {
    auto report = make_empty_report();
    auto unit = make_unit(1, true);
    unit.device_id_supported = true;
    unit.device_vendor = "Schneider";
    unit.device_product_code = "M340";
    unit.device_revision = "2.1.0";
    report.results.push_back(unit);

    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"device_identification\"");
    ASSERT_STR_CONTAINS(json, "\"vendor\": \"Schneider\"");
    ASSERT_STR_CONTAINS(json, "\"product_code\": \"M340\"");
    ASSERT_STR_CONTAINS(json, "\"revision\": \"2.1.0\"");
}

// ===========================================================================
// Findings in JSON
// ===========================================================================

TEST(report_findings_in_json) {
    auto report = make_empty_report();
    auto unit = make_unit(1, true);
    unit.findings.push_back({FindingSeverity::CRITICAL, "unauthorized_write", "Write access"});
    unit.findings.push_back({FindingSeverity::HIGH, "unauthorized_read", "Read access"});
    report.results.push_back(unit);

    auto json = ReportGenerator::to_json(report);
    ASSERT_STR_CONTAINS(json, "\"findings\"");
    ASSERT_STR_CONTAINS(json, "\"severity\": \"CRITICAL\"");
    ASSERT_STR_CONTAINS(json, "\"severity\": \"HIGH\"");
}

// ===========================================================================
// Severity helper
// ===========================================================================

TEST(severity_to_string_values) {
    ASSERT_EQ(severity_to_string(FindingSeverity::INFO), "INFO");
    ASSERT_EQ(severity_to_string(FindingSeverity::MEDIUM), "MEDIUM");
    ASSERT_EQ(severity_to_string(FindingSeverity::HIGH), "HIGH");
    ASSERT_EQ(severity_to_string(FindingSeverity::CRITICAL), "CRITICAL");
}
