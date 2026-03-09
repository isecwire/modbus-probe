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

// ---------------------------------------------------------------------------
// Register dump table
// ---------------------------------------------------------------------------

std::string TableFormatter::format_register_table(const UnitResult& unit, bool color) {
    std::ostringstream os;
    const char* bold  = color ? ansi::BOLD : "";
    const char* reset = color ? ansi::RESET : "";

    if (!unit.holding_registers.empty()) {
        os << "\n" << bold << "  Holding Registers (Unit " << static_cast<int>(unit.unit_id) << ")" << reset << "\n";
        std::vector<size_t> rw = {10, 10, 8};
        os << "  " << top_border(rw);
        os << "  " << row({"Address", "Hex", "Decimal"}, rw);
        os << "  " << mid_border(rw);
        for (const auto& reg : unit.holding_registers) {
            std::ostringstream hex;
            hex << "0x" << std::setfill('0') << std::setw(4) << std::hex << reg.value;
            os << "  " << row({std::to_string(reg.address), hex.str(), std::to_string(reg.value)}, rw);
        }
        os << "  " << bot_border(rw);
    }

    if (!unit.input_registers.empty()) {
        os << "\n" << bold << "  Input Registers (Unit " << static_cast<int>(unit.unit_id) << ")" << reset << "\n";
        std::vector<size_t> rw = {10, 10, 8};
        os << "  " << top_border(rw);
        os << "  " << row({"Address", "Hex", "Decimal"}, rw);
        os << "  " << mid_border(rw);
        for (const auto& reg : unit.input_registers) {
            std::ostringstream hex;
            hex << "0x" << std::setfill('0') << std::setw(4) << std::hex << reg.value;
            os << "  " << row({std::to_string(reg.address), hex.str(), std::to_string(reg.value)}, rw);
        }
        os << "  " << bot_border(rw);
    }

    return os.str();
}

// ---------------------------------------------------------------------------
// Coil status table
// ---------------------------------------------------------------------------

std::string TableFormatter::format_coil_table(const UnitResult& unit, bool color) {
    std::ostringstream os;
    if (unit.coils.empty()) return os.str();

    const char* bold  = color ? ansi::BOLD : "";
    const char* reset = color ? ansi::RESET : "";
    const char* green = color ? ansi::GREEN : "";
    const char* red   = color ? ansi::RED : "";

    os << "\n" << bold << "  Coils (Unit " << static_cast<int>(unit.unit_id) << ")" << reset << "\n";
    std::vector<size_t> cw = {10, 8};
    os << "  " << top_border(cw);
    os << "  " << row({"Address", "State"}, cw);
    os << "  " << mid_border(cw);
    for (const auto& [addr, val] : unit.coils) {
        std::string state = val
            ? std::string(red) + "ON" + reset
            : std::string(green) + "OFF" + reset;
        os << "  " << row({std::to_string(addr), state}, cw);
    }
    os << "  " << bot_border(cw);

    return os.str();
}

// ---------------------------------------------------------------------------
// Fuzz results table
// ---------------------------------------------------------------------------

std::string TableFormatter::format_fuzz_table(const std::vector<FuzzEntry>& entries,
                                               uint8_t unit_id, bool color) {
    std::ostringstream os;
    if (entries.empty()) return os.str();

    const char* bold  = color ? ansi::BOLD : "";
    const char* reset = color ? ansi::RESET : "";
    const char* green = color ? ansi::GREEN : "";
    const char* red   = color ? ansi::RED : "";
    const char* yel   = color ? ansi::YELLOW : "";
    const char* dim   = color ? ansi::DIM : "";

    os << "\n" << bold << "  Function Code Fuzz Results (Unit " << static_cast<int>(unit_id) << ")" << reset << "\n";
    std::vector<size_t> fw = {6, 10, 38, 10};
    os << "  " << top_border(fw);
    os << "  " << row({"FC", "Result", "Description", "Time (ms)"}, fw);
    os << "  " << mid_border(fw);

    for (const auto& e : entries) {
        std::string fc_str = "0x" + ([&]{
            std::ostringstream h; h << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(e.function_code);
            return h.str();
        })();

        std::string result_str;
        switch (e.result_type) {
            case FuzzResultType::Supported:
                result_str = std::string(green) + "SUPPORTED" + reset;
                break;
            case FuzzResultType::Exception:
                result_str = std::string(yel) + "EXCEPTION" + reset;
                break;
            case FuzzResultType::Timeout:
                result_str = std::string(dim) + "TIMEOUT" + reset;
                break;
            case FuzzResultType::Error:
                result_str = std::string(red) + "ERROR" + reset;
                break;
        }

        std::ostringstream time_str;
        time_str << std::fixed << std::setprecision(1) << e.response_time_ms;

        os << "  " << row({fc_str, result_str, e.description, time_str.str()}, fw);
    }
    os << "  " << bot_border(fw);

    return os.str();
}

// ---------------------------------------------------------------------------
// Device Identification table
// ---------------------------------------------------------------------------

std::string TableFormatter::format_device_id_table(const DeviceIdentification& id,
                                                     uint8_t unit_id, bool color) {
    std::ostringstream os;
    if (!id.supported) return os.str();

    const char* bold  = color ? ansi::BOLD : "";
    const char* reset = color ? ansi::RESET : "";

    os << "\n" << bold << "  Device Identification (Unit " << static_cast<int>(unit_id) << ")" << reset << "\n";
    std::vector<size_t> dw = {22, 44};
    os << "  " << top_border(dw);
    os << "  " << row({"Property", "Value"}, dw);
    os << "  " << mid_border(dw);

    auto add_row = [&](const std::string& key, const std::string& val) {
        if (!val.empty()) {
            os << "  " << row({key, val}, dw);
        }
    };

    add_row("Vendor Name", id.vendor_name);
    add_row("Product Code", id.product_code);
    add_row("Revision", id.revision);
    add_row("Vendor URL", id.vendor_url);
    add_row("Product Name", id.product_name);
    add_row("Model Name", id.model_name);
    add_row("User Application", id.user_application_name);

    for (const auto& [oid, val] : id.extended_objects) {
        add_row(DeviceIdParser::object_id_name(oid), val);
    }

    os << "  " << bot_border(dw);
    return os.str();
}

// ---------------------------------------------------------------------------
// Timing analysis table
// ---------------------------------------------------------------------------

std::string TableFormatter::format_timing_table(const ScanReport& report, bool color) {
    std::ostringstream os;
    if (report.results.empty()) return os.str();

    const char* bold  = color ? ansi::BOLD : "";
    const char* reset = color ? ansi::RESET : "";
    const char* green = color ? ansi::GREEN : "";
    const char* yel   = color ? ansi::YELLOW : "";
    const char* red   = color ? ansi::RED : "";

    os << "\n" << bold << "  Response Timing Analysis" << reset << "\n";
    std::vector<size_t> tw = {8, 14, 14, 14, 10};
    os << "  " << top_border(tw);
    os << "  " << row({"Unit", "Min (ms)", "Avg (ms)", "Max (ms)", "Rating"}, tw);
    os << "  " << mid_border(tw);

    for (const auto& r : report.results) {
        if (!r.responsive) continue;
        if (r.timing_samples.empty()) continue;

        double min_t = r.timing_samples[0];
        double max_t = r.timing_samples[0];
        double sum = 0;
        for (double t : r.timing_samples) {
            if (t < min_t) min_t = t;
            if (t > max_t) max_t = t;
            sum += t;
        }
        double avg_t = sum / static_cast<double>(r.timing_samples.size());

        auto fmt = [](double v) {
            std::ostringstream s;
            s << std::fixed << std::setprecision(1) << v;
            return s.str();
        };

        std::string rating;
        if (avg_t < 50.0) {
            rating = std::string(green) + "FAST" + reset;
        } else if (avg_t < 200.0) {
            rating = std::string(yel) + "NORMAL" + reset;
        } else {
            rating = std::string(red) + "SLOW" + reset;
        }

        os << "  " << row({std::to_string(r.unit_id), fmt(min_t), fmt(avg_t), fmt(max_t), rating}, tw);
    }
    os << "  " << bot_border(tw);

    return os.str();
}

// ---------------------------------------------------------------------------
// CSV formatter
// ---------------------------------------------------------------------------

std::string CsvFormatter::escape_csv(const std::string& s) {
    if (s.find_first_of(",\"\n\r") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

std::string CsvFormatter::format_csv(const ScanReport& report) {
    std::ostringstream os;
    os << "unit_id,responsive,holding_regs_readable,input_regs_readable,"
       << "coils_readable,write_tested,write_vulnerable,severity,detail\n";

    for (const auto& r : report.results) {
        if (!r.responsive) continue;

        std::string severity;
        if (r.write_test_vulnerable) severity = "CRITICAL";
        else if (r.holding_registers_readable || r.input_registers_readable || r.coils_readable) severity = "HIGH";
        else severity = "MEDIUM";

        os << static_cast<int>(r.unit_id) << ","
           << (r.responsive ? "true" : "false") << ","
           << (r.holding_registers_readable ? "true" : "false") << ","
           << (r.input_registers_readable ? "true" : "false") << ","
           << (r.coils_readable ? "true" : "false") << ","
           << (r.write_test_performed ? "true" : "false") << ","
           << (r.write_test_vulnerable ? "true" : "false") << ","
           << severity << ","
           << escape_csv(r.write_test_detail) << "\n";
    }
    return os.str();
}

std::string CsvFormatter::format_findings_csv(const ScanReport& report) {
    std::ostringstream os;
    os << "severity,unit_id,finding_type,detail\n";

    for (const auto& r : report.results) {
        if (!r.responsive) continue;

        if (r.write_test_vulnerable) {
            os << "CRITICAL," << static_cast<int>(r.unit_id)
               << ",unauthorized_write," << escape_csv(r.write_test_detail) << "\n";
        }
        if (r.holding_registers_readable) {
            os << "HIGH," << static_cast<int>(r.unit_id)
               << ",holding_registers_readable,Unauthenticated read access\n";
        }
        if (r.input_registers_readable) {
            os << "HIGH," << static_cast<int>(r.unit_id)
               << ",input_registers_readable,Unauthenticated read access\n";
        }
        if (r.coils_readable) {
            os << "HIGH," << static_cast<int>(r.unit_id)
               << ",coils_readable,Unauthenticated read access\n";
        }
        if (!r.holding_registers_readable && !r.input_registers_readable &&
            !r.coils_readable && !r.write_test_vulnerable) {
            os << "MEDIUM," << static_cast<int>(r.unit_id)
               << ",device_info_leak,Unit responsive to probes\n";
        }
    }
    return os.str();
}

}  // namespace modbus_probe
