#include "table_formatter.h"
#include "device_id.h"
#include "fuzzer.h"
#include "progress.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace modbus_probe {

OutputFormat parse_output_format(const std::string& s) {
    if (s == "csv")   return OutputFormat::CSV;
    if (s == "table") return OutputFormat::Table;
    return OutputFormat::JSON;
}

// ---------------------------------------------------------------------------
// Box-drawing table helpers (Unicode box chars for professional look)
// ---------------------------------------------------------------------------

static constexpr const char* BOX_TL = "\xe2\x94\x8c";  // top-left
static constexpr const char* BOX_TR = "\xe2\x94\x90";  // top-right
static constexpr const char* BOX_BL = "\xe2\x94\x94";  // bottom-left
static constexpr const char* BOX_BR = "\xe2\x94\x98";  // bottom-right
static constexpr const char* BOX_H  = "\xe2\x94\x80";  // horizontal
static constexpr const char* BOX_V  = "\xe2\x94\x82";  // vertical
static constexpr const char* BOX_TM = "\xe2\x94\xac";  // top-mid
static constexpr const char* BOX_BM = "\xe2\x94\xb4";  // bottom-mid
static constexpr const char* BOX_LM = "\xe2\x94\x9c";  // left-mid
static constexpr const char* BOX_RM = "\xe2\x94\xa4";  // right-mid
static constexpr const char* BOX_CM = "\xe2\x94\xbc";  // cross-mid

static std::string repeat_str(const char* s, size_t n) {
    std::string result;
    for (size_t i = 0; i < n; ++i) result += s;
    return result;
}

std::string TableFormatter::top_border(const std::vector<size_t>& widths) {
    std::string line = BOX_TL;
    for (size_t i = 0; i < widths.size(); ++i) {
        line += repeat_str(BOX_H, widths[i] + 2);
        line += (i + 1 < widths.size()) ? BOX_TM : BOX_TR;
    }
    line += "\n";
    return line;
}

std::string TableFormatter::mid_border(const std::vector<size_t>& widths) {
    std::string line = BOX_LM;
    for (size_t i = 0; i < widths.size(); ++i) {
        line += repeat_str(BOX_H, widths[i] + 2);
        line += (i + 1 < widths.size()) ? BOX_CM : BOX_RM;
    }
    line += "\n";
    return line;
}

std::string TableFormatter::bot_border(const std::vector<size_t>& widths) {
    std::string line = BOX_BL;
    for (size_t i = 0; i < widths.size(); ++i) {
        line += repeat_str(BOX_H, widths[i] + 2);
        line += (i + 1 < widths.size()) ? BOX_BM : BOX_BR;
    }
    line += "\n";
    return line;
}

size_t TableFormatter::visible_length(const std::string& s) {
    // Strip ANSI escape sequences for width calculation
    size_t len = 0;
    bool in_escape = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\033') {
            in_escape = true;
            continue;
        }
        if (in_escape) {
            if ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
                in_escape = false;
            }
            continue;
        }
        ++len;
    }
    return len;
}

std::string TableFormatter::pad(const std::string& s, size_t width) {
    size_t vis = visible_length(s);
    if (vis >= width) return s;
    return s + std::string(width - vis, ' ');
}

std::string TableFormatter::row(const std::vector<std::string>& cells,
                                 const std::vector<size_t>& widths) {
    std::string line = BOX_V;
    for (size_t i = 0; i < cells.size() && i < widths.size(); ++i) {
        line += " " + pad(cells[i], widths[i]) + " " + BOX_V;
    }
    line += "\n";
    return line;
}

// Unused generic helper retained for API completeness
std::string TableFormatter::h_line(const std::vector<size_t>& widths,
                                    char /*left*/, char /*mid*/, char /*right*/, char /*fill*/) {
    return mid_border(widths);
}

// ---------------------------------------------------------------------------
// Main summary table
// ---------------------------------------------------------------------------

std::string TableFormatter::format_table(const ScanReport& report, bool color) {
    std::ostringstream os;

    const char* bold  = color ? ansi::BOLD : "";
    const char* reset = color ? ansi::RESET : "";
    const char* cyan  = color ? ansi::CYAN : "";
    const char* green = color ? ansi::GREEN : "";
    const char* red   = color ? ansi::RED : "";
    const char* yel   = color ? ansi::YELLOW : "";

    // Summary header
    os << "\n" << bold << "  Scan Summary" << reset << "\n";
    std::vector<size_t> sw = {24, 40};
    os << "  " << top_border(sw);
    os << "  " << row({"Target", report.target_host + ":" + std::to_string(report.target_port)}, sw);
    os << "  " << mid_border(sw);
    os << "  " << row({"Scan Start", report.scan_start}, sw);
    os << "  " << row({"Scan End", report.scan_end}, sw);
    os << "  " << mid_border(sw);
    os << "  " << row({"Units Scanned", std::to_string(report.units_scanned)}, sw);
    os << "  " << row({"Units Responsive", std::to_string(report.units_responsive)}, sw);
    os << "  " << row({"Unauthenticated Reads",
                        std::string(report.unauthenticated_reads > 0 ? yel : green) +
                        std::to_string(report.unauthenticated_reads) + reset}, sw);
    os << "  " << row({"Unauthenticated Writes",
                        std::string(report.unauthenticated_writes > 0 ? red : green) +
                        std::to_string(report.unauthenticated_writes) + reset}, sw);
    os << "  " << bot_border(sw);

    // Per-unit results
    if (!report.results.empty()) {
        os << "\n" << bold << "  Responsive Units" << reset << "\n";
        std::vector<size_t> uw = {8, 14, 14, 10, 12, 10};
        os << "  " << top_border(uw);
        os << "  " << row({"Unit", "Hold.Regs", "Input.Regs", "Coils", "Write Vuln", "Severity"}, uw);
        os << "  " << mid_border(uw);

        for (const auto& r : report.results) {
            if (!r.responsive) continue;

            std::string hr = r.holding_registers_readable
                ? std::string(yel) + "READABLE" + reset
                : std::string(green) + "DENIED" + reset;
            std::string ir = r.input_registers_readable
                ? std::string(yel) + "READABLE" + reset
                : std::string(green) + "DENIED" + reset;
            std::string cr = r.coils_readable
                ? std::string(yel) + "READABLE" + reset
                : std::string(green) + "DENIED" + reset;
            std::string wv = r.write_test_performed
                ? (r.write_test_vulnerable
                    ? std::string(red) + "YES" + reset
                    : std::string(green) + "NO" + reset)
                : std::string(cyan) + "N/A" + reset;

            // Determine severity
            std::string sev;
            if (r.write_test_vulnerable) {
                sev = std::string(red) + "CRITICAL" + reset;
            } else if (r.holding_registers_readable || r.input_registers_readable || r.coils_readable) {
                sev = std::string(yel) + "HIGH" + reset;
            } else {
                sev = std::string(green) + "INFO" + reset;
            }

            os << "  " << row({std::to_string(r.unit_id), hr, ir, cr, wv, sev}, uw);
        }
        os << "  " << bot_border(uw);
    }

    return os.str();
}

// ---------------------------------------------------------------------------
// Findings table (flat list of security findings)
// ---------------------------------------------------------------------------

std::string TableFormatter::format_findings_table(const ScanReport& report, bool color) {
    std::ostringstream os;
    const char* bold  = color ? ansi::BOLD : "";
    const char* reset = color ? ansi::RESET : "";
    const char* red   = color ? ansi::RED : "";
    const char* yel   = color ? ansi::YELLOW : "";
    const char* cyan  = color ? ansi::CYAN : "";

    os << "\n" << bold << "  Security Findings" << reset << "\n";
    std::vector<size_t> fw = {8, 10, 50};
    os << "  " << top_border(fw);
    os << "  " << row({"Severity", "Unit ID", "Finding"}, fw);
    os << "  " << mid_border(fw);

    for (const auto& r : report.results) {
        if (!r.responsive) continue;

        if (r.write_test_vulnerable) {
            os << "  " << row({
                std::string(red) + "CRITICAL" + reset,
                std::to_string(r.unit_id),
                "Unauthorized write access: " + r.write_test_detail
            }, fw);
        }
        if (r.holding_registers_readable) {
            os << "  " << row({
                std::string(yel) + "HIGH" + reset,
                std::to_string(r.unit_id),
                "Holding registers readable without authentication"
            }, fw);
        }
        if (r.input_registers_readable) {
            os << "  " << row({
                std::string(yel) + "HIGH" + reset,
                std::to_string(r.unit_id),
                "Input registers readable without authentication"
            }, fw);
        }
        if (r.coils_readable) {
            os << "  " << row({
                std::string(yel) + "HIGH" + reset,
                std::to_string(r.unit_id),
                "Coils readable without authentication"
            }, fw);
        }
        if (r.responsive && !r.holding_registers_readable &&
            !r.input_registers_readable && !r.coils_readable &&
            !r.write_test_vulnerable) {
            os << "  " << row({
                std::string(cyan) + "MEDIUM" + reset,
                std::to_string(r.unit_id),
                "Unit responsive (device information leak)"
            }, fw);
        }
    }
    os << "  " << bot_border(fw);

    return os.str();
}
