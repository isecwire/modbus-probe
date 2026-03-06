#pragma once
// ---------------------------------------------------------------------------
// table_formatter.h -- ASCII table and CSV output formatters
//
// Renders scan results as formatted ASCII tables (with box-drawing chars),
// CSV, or enhanced JSON.  Designed for terminal display and pipeline export.
// ---------------------------------------------------------------------------

#include "device_id.h"
#include "fuzzer.h"
#include "report.h"

#include <string>
#include <vector>

namespace modbus_probe {

enum class OutputFormat {
    JSON,
    CSV,
    Table,
};

// Parse --format argument
OutputFormat parse_output_format(const std::string& s);

class TableFormatter {
public:
    // Render a full scan report as an ASCII table
    static std::string format_table(const ScanReport& report, bool color = true);

    // Render findings table (one row per security finding with severity)
    static std::string format_findings_table(const ScanReport& report, bool color = true);

    // Render register dump table for a unit
    static std::string format_register_table(const UnitResult& unit, bool color = true);

    // Render coil status table for a unit
    static std::string format_coil_table(const UnitResult& unit, bool color = true);

    // Render fuzzing results table
    static std::string format_fuzz_table(const std::vector<FuzzEntry>& entries,
                                          uint8_t unit_id, bool color = true);

    // Render device identification table
    static std::string format_device_id_table(const DeviceIdentification& id,
                                               uint8_t unit_id, bool color = true);

    // Render timing analysis table
    static std::string format_timing_table(const ScanReport& report, bool color = true);

private:
    // Box-drawing helpers
    static std::string h_line(const std::vector<size_t>& widths, char left, char mid, char right, char fill);
    static std::string top_border(const std::vector<size_t>& widths);
    static std::string mid_border(const std::vector<size_t>& widths);
    static std::string bot_border(const std::vector<size_t>& widths);
    static std::string row(const std::vector<std::string>& cells,
                           const std::vector<size_t>& widths);
    static std::string pad(const std::string& s, size_t width);
    static size_t visible_length(const std::string& s);
};

class CsvFormatter {
public:
    // Render a full scan report as CSV
    static std::string format_csv(const ScanReport& report);

    // Render findings as CSV (one row per finding)
    static std::string format_findings_csv(const ScanReport& report);

private:
    static std::string escape_csv(const std::string& s);
};

}  // namespace modbus_probe
