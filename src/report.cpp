#include "report.h"

#include <fstream>
#include <iomanip>
#include <sstream>

namespace modbus_probe {

std::string severity_to_string(FindingSeverity sev) {
    switch (sev) {
        case FindingSeverity::INFO:     return "INFO";
        case FindingSeverity::MEDIUM:   return "MEDIUM";
        case FindingSeverity::HIGH:     return "HIGH";
        case FindingSeverity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

std::string ReportGenerator::escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string ReportGenerator::indent(int level) {
    return std::string(static_cast<size_t>(level) * 2, ' ');
}

std::string ReportGenerator::to_json(const ScanReport& report) {
    std::ostringstream os;

    os << "{\n";
    os << indent(1) << "\"tool\": \"modbus-probe\",\n";
    os << indent(1) << "\"version\": \"" << escape_json(report.tool_version.empty() ? "2.2.0" : report.tool_version) << "\",\n";
    os << indent(1) << "\"target_host\": \"" << escape_json(report.target_host) << "\",\n";
    os << indent(1) << "\"target_port\": " << report.target_port << ",\n";
    os << indent(1) << "\"protocol_mode\": \"" << escape_json(report.protocol_mode.empty() ? "tcp" : report.protocol_mode) << "\",\n";
    os << indent(1) << "\"scan_start\": \"" << escape_json(report.scan_start) << "\",\n";
    os << indent(1) << "\"scan_end\": \"" << escape_json(report.scan_end) << "\",\n";
    os << indent(1) << "\"summary\": {\n";
    os << indent(2) << "\"units_scanned\": " << report.units_scanned << ",\n";
    os << indent(2) << "\"units_responsive\": " << report.units_responsive << ",\n";
    os << indent(2) << "\"unauthenticated_reads\": " << report.unauthenticated_reads << ",\n";
    os << indent(2) << "\"unauthenticated_writes\": " << report.unauthenticated_writes << ",\n";
    os << indent(2) << "\"devices_identified\": " << report.devices_identified << ",\n";
    os << indent(2) << "\"thread_count\": " << report.thread_count << "\n";
    os << indent(1) << "},\n";

    os << indent(1) << "\"results\": [\n";
    bool first_result = true;
    for (const auto& r : report.results) {
        if (!r.responsive) continue;

        if (!first_result) os << ",\n";
        first_result = false;

        os << indent(2) << "{\n";
        os << indent(3) << "\"unit_id\": " << static_cast<int>(r.unit_id) << ",\n";
        os << indent(3) << "\"responsive\": true,\n";

        // Device identification
        if (r.device_id_supported) {
            os << indent(3) << "\"device_identification\": {\n";
            os << indent(4) << "\"supported\": true,\n";
            os << indent(4) << "\"vendor\": \"" << escape_json(r.device_vendor) << "\",\n";
            os << indent(4) << "\"product_code\": \"" << escape_json(r.device_product_code) << "\",\n";
            os << indent(4) << "\"revision\": \"" << escape_json(r.device_revision) << "\",\n";
            os << indent(4) << "\"vendor_url\": \"" << escape_json(r.device_vendor_url) << "\",\n";
            os << indent(4) << "\"product_name\": \"" << escape_json(r.device_product_name) << "\",\n";
            os << indent(4) << "\"model_name\": \"" << escape_json(r.device_model_name) << "\"\n";
            os << indent(3) << "},\n";
        }

        // Holding registers
        os << indent(3) << "\"holding_registers\": {\n";
        os << indent(4) << "\"readable\": " << (r.holding_registers_readable ? "true" : "false") << ",\n";
        os << indent(4) << "\"count\": " << r.holding_registers.size() << ",\n";
        os << indent(4) << "\"data\": [";
        for (size_t j = 0; j < r.holding_registers.size(); ++j) {
            if (j > 0) os << ", ";
            os << "{\"address\": " << r.holding_registers[j].address
               << ", \"value\": " << r.holding_registers[j].value << "}";
        }
        os << "]\n";
        os << indent(3) << "},\n";

        // Input registers
        os << indent(3) << "\"input_registers\": {\n";
        os << indent(4) << "\"readable\": " << (r.input_registers_readable ? "true" : "false") << ",\n";
        os << indent(4) << "\"count\": " << r.input_registers.size() << ",\n";
        os << indent(4) << "\"data\": [";
        for (size_t j = 0; j < r.input_registers.size(); ++j) {
            if (j > 0) os << ", ";
            os << "{\"address\": " << r.input_registers[j].address
               << ", \"value\": " << r.input_registers[j].value << "}";
        }
        os << "]\n";
        os << indent(3) << "},\n";

        // Coils
        os << indent(3) << "\"coils\": {\n";
        os << indent(4) << "\"readable\": " << (r.coils_readable ? "true" : "false") << ",\n";
        os << indent(4) << "\"count\": " << r.coils.size() << ",\n";
        os << indent(4) << "\"data\": [";
        for (size_t j = 0; j < r.coils.size(); ++j) {
            if (j > 0) os << ", ";
            os << "{\"address\": " << r.coils[j].first
               << ", \"value\": " << (r.coils[j].second ? "true" : "false") << "}";
        }
        os << "]\n";
        os << indent(3) << "},\n";

        // Write test
        os << indent(3) << "\"write_test\": {\n";
        os << indent(4) << "\"performed\": " << (r.write_test_performed ? "true" : "false") << ",\n";
        os << indent(4) << "\"vulnerable\": " << (r.write_test_vulnerable ? "true" : "false") << ",\n";
        os << indent(4) << "\"detail\": \"" << escape_json(r.write_test_detail) << "\"\n";
        os << indent(3) << "},\n";

        // Timing
        if (!r.timing_samples.empty()) {
            double min_t = r.timing_samples[0], max_t = r.timing_samples[0], sum = 0;
            for (double t : r.timing_samples) {
                if (t < min_t) min_t = t;
                if (t > max_t) max_t = t;
                sum += t;
            }
            double avg_t = sum / static_cast<double>(r.timing_samples.size());

            os << indent(3) << "\"timing\": {\n";
            os << indent(4) << "\"samples\": " << r.timing_samples.size() << ",\n";
            os << indent(4) << std::fixed << std::setprecision(2);
            os << indent(4) << "\"min_ms\": " << min_t << ",\n";
            os << indent(4) << "\"avg_ms\": " << avg_t << ",\n";
            os << indent(4) << "\"max_ms\": " << max_t << "\n";
            os << indent(3) << "},\n";
        }

        // Supported function codes (from fuzzing)
        if (!r.supported_function_codes.empty()) {
            os << indent(3) << "\"supported_function_codes\": [";
            for (size_t j = 0; j < r.supported_function_codes.size(); ++j) {
                if (j > 0) os << ", ";
                os << static_cast<int>(r.supported_function_codes[j]);
            }
            os << "],\n";
        }

        // Findings
        if (!r.findings.empty()) {
            os << indent(3) << "\"findings\": [\n";
            for (size_t j = 0; j < r.findings.size(); ++j) {
                const auto& f = r.findings[j];
                os << indent(4) << "{"
                   << "\"severity\": \"" << severity_to_string(f.severity) << "\", "
                   << "\"category\": \"" << escape_json(f.category) << "\", "
                   << "\"description\": \"" << escape_json(f.description) << "\""
                   << "}";
                if (j + 1 < r.findings.size()) os << ",";
                os << "\n";
            }
            os << indent(3) << "],\n";
        }

        // Error (last field before closing brace -- strip trailing comma)
        if (!r.error.empty()) {
            os << indent(3) << "\"error\": \"" << escape_json(r.error) << "\"\n";
        } else {
            // Remove trailing comma from previous field by rewriting
            // Simple approach: add a harmless field
            os << indent(3) << "\"_complete\": true\n";
        }

        os << indent(2) << "}";
    }
    os << "\n";
    os << indent(1) << "]\n";
    os << "}\n";

    return os.str();
}

bool ReportGenerator::write_file(const std::string& path, const ScanReport& report) {
    std::ofstream ofs(path);
    if (!ofs.is_open()) return false;
    ofs << to_json(report);
    return ofs.good();
}

}  // namespace modbus_probe
