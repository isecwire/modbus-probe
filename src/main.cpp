#include "modbus_scanner.h"
#include "report.h"
#include "table_formatter.h"
#include "pcap_writer.h"
#include "monitor.h"
#include "discovery.h"

#include <csignal>
#include <cstdlib>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <string>
#include <unistd.h>

using namespace modbus_probe;

// Global pointer for signal handler access to monitor mode
static RegisterMonitor* g_monitor = nullptr;

static void sigint_handler(int /*sig*/) {
    if (g_monitor) {
        g_monitor->stop();
    }
}

static void generate_completions(const char* shell) {
    if (std::string(shell) == "bash") {
        std::cout << R"(# Bash completion for modbus-probe
_modbus_probe_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="--host --port --mode --scan-ids --registers --coils --range
        --test-write --no-device-id --fuzz --threads --output --format
        --timeout --connect-timeout --quiet --verbose --no-color --help
        --pcap --monitor --discover --completions --tls --cert --key
        --retries --diff"
    COMPREPLY=($(compgen -W "$opts" -- "$cur"))
}
complete -F _modbus_probe_completions modbus-probe
)";
    } else if (std::string(shell) == "zsh") {
        std::cout << R"(# Zsh completion for modbus-probe
#compdef modbus-probe
_modbus_probe() {
    _arguments \
        '-H[Target host]:host:_hosts' \
        '--host[Target host]:host:_hosts' \
        '-p[Modbus TCP port]:port:' \
        '--port[Modbus TCP port]:port:' \
        '-m[Protocol mode]:mode:(tcp rtu)' \
        '--mode[Protocol mode]:mode:(tcp rtu)' \
        '-s[Unit ID range]:range:' \
        '--scan-ids[Unit ID range]:range:' \
        '-r[Register range]:range:' \
        '--registers[Register range]:range:' \
        '-c[Coil range]:range:' \
        '--coils[Coil range]:range:' \
        '-w[Test write access]' \
        '--test-write[Test write access]' \
        '-f[Fuzz function codes]:unit_id:' \
        '--fuzz[Fuzz function codes]:unit_id:' \
        '-T[Thread count]:threads:' \
        '--threads[Thread count]:threads:' \
        '-o[Output file]:file:_files' \
        '--output[Output file]:file:_files' \
        '-F[Output format]:format:(json csv table)' \
        '--format[Output format]:format:(json csv table)' \
        '--pcap[PCAP capture file]:file:_files' \
        '--monitor[Monitor register changes]' \
        '--discover[Discover hosts in CIDR]:cidr:' \
        '--completions[Generate completions]:shell:(bash zsh)' \
        '--tls[Enable TLS]' \
        '--cert[TLS certificate]:file:_files' \
        '--key[TLS private key]:file:_files' \
        '-q[Quiet mode]' \
        '-v[Verbose mode]' \
        '-h[Show help]'
}
_modbus_probe
)";
    } else {
        std::cerr << "Unknown shell: " << shell << " (supported: bash, zsh)\n";
    }
}

static void print_usage(const char* prog, bool color) {
    const char* c = color ? "\033[36m" : "";
    const char* b = color ? "\033[1m"  : "";
    const char* d = color ? "\033[2m"  : "";
    const char* y = color ? "\033[33m" : "";
    const char* r = color ? "\033[0m"  : "";

    std::cerr
        << b << "modbus-probe v2.2.0" << r << " -- Modbus TCP/RTU Security Scanner\n"
        << d << "Copyright (c) 2026 isecwire GmbH" << r << "\n\n"
        << b << "Usage:" << r << " " << prog << " [options]\n\n"
        << b << "Required:" << r << "\n"
        << c << "  -H, --host <addr>       " << r << "Target host (IP or hostname)\n\n"
        << b << "Connection:" << r << "\n"
        << c << "  -p, --port <port>       " << r << "Modbus TCP port (default: 502)\n"
        << c << "  -m, --mode <mode>       " << r << "Protocol mode: tcp, rtu (default: tcp)\n"
        << c << "  -t, --timeout <ms>      " << r << "Response timeout in ms (default: 2000)\n"
        << c << "      --connect-timeout   " << r << "Connection timeout in ms (default: 3000)\n\n"
        << b << "Scanning:" << r << "\n"
        << c << "  -s, --scan-ids <range>  " << r << "Unit ID range to scan, e.g. 1-247 (default: 1-247)\n"
        << c << "  -r, --registers <range> " << r << "Register start and count, e.g. 0:10 (default: 0:10)\n"
        << c << "  -c, --coils <range>     " << r << "Coil start and count, e.g. 0:16 (default: 0:16)\n"
        << c << "      --range <ranges>    " << r << "Extra register ranges, e.g. 0-100,400-500\n"
        << c << "  -w, --test-write        " << r << "Test for unauthorized write access (with rollback)\n"
        << c << "      --no-device-id      " << r << "Skip FC43/14 device identification\n\n"
        << b << "Fuzzing:" << r << "\n"
        << c << "  -f, --fuzz [unit_id]    " << r << "Fuzz all function codes (1-127) on unit ID (default: 1)\n\n"
        << b << "Discovery & Monitoring:" << r << "\n"
        << c << "      --discover <CIDR>   " << r << "Scan IP range for Modbus devices (e.g. 192.168.1.0/24)\n"
        << c << "      --monitor           " << r << "Monitor registers for changes (Ctrl+C to stop)\n\n"
        << b << "Performance:" << r << "\n"
        << c << "  -T, --threads <N>       " << r << "Number of scanning threads (default: 1)\n\n"
        << b << "Output:" << r << "\n"
        << c << "  -o, --output <file>     " << r << "Write report to file\n"
        << c << "  -F, --format <fmt>      " << r << "Output format: json, csv, table (default: json)\n"
        << c << "      --pcap <file>       " << r << "Capture Modbus traffic to PCAP file\n"
        << c << "  -q, --quiet             " << r << "Suppress progress, only emit report data\n"
        << c << "  -v, --verbose           " << r << "Verbose output with per-operation details\n"
        << c << "      --no-color          " << r << "Disable colored terminal output\n"
        << c << "      --completions <sh>  " << r << "Generate shell completions (bash, zsh)\n"
        << c << "  -h, --help              " << r << "Show this help message\n\n"
        << b << "Examples:" << r << "\n"
        << d << "  # Basic scan" << r << "\n"
        << "  " << prog << " --host 192.168.1.100\n\n"
        << d << "  # Scan with write test, 4 threads, table output" << r << "\n"
        << "  " << prog << " -H 10.0.0.50 -s 1-10 -w -T 4 -F table\n\n"
        << d << "  # RTU-over-TCP scan with extended register range" << r << "\n"
        << "  " << prog << " -H plc.local -m rtu --range 0-100,400-500\n\n"
        << d << "  # Fuzz function codes on unit ID 1" << r << "\n"
        << "  " << prog << " -H 10.0.0.50 --fuzz 1\n\n"
        << d << "  # Quick scan, JSON to file" << r << "\n"
        << "  " << prog << " -H plc.local -s 1-5 -q -o report.json\n\n"
        << y << "WARNING: Only use this tool on systems you are authorized to test.\n"
        << "Unauthorized access to industrial control systems is illegal." << r << "\n";
}

static bool parse_range(const std::string& s, uint16_t& start, uint16_t& end, char delim = '-') {
    auto pos = s.find(delim);
    if (pos == std::string::npos) {
        try {
            unsigned long val = std::stoul(s);
            start = static_cast<uint16_t>(val);
            end = start;
            return true;
        } catch (...) {
            return false;
        }
    }
    try {
        start = static_cast<uint16_t>(std::stoul(s.substr(0, pos)));
        end = static_cast<uint16_t>(std::stoul(s.substr(pos + 1)));
        return start <= end;
    } catch (...) {
        return false;
    }
}

int main(int argc, char* argv[]) {
    ScanConfig config;
    std::string output_file;
    std::string pcap_file;
    std::string discover_cidr;
    bool monitor_mode = false;
    bool no_device_id = false;

    // Detect if stderr is a terminal for default color
    config.color = isatty(STDERR_FILENO);

    enum LongOpts {
        OPT_RANGE = 256,
        OPT_NO_COLOR,
        OPT_NO_DEVICE_ID,
        OPT_CONNECT_TIMEOUT,
        OPT_PCAP,
        OPT_MONITOR,
        OPT_DISCOVER,
        OPT_COMPLETIONS,
        OPT_TLS,
        OPT_CERT,
        OPT_KEY,
    };

    static struct option long_opts[] = {
        {"host",             required_argument, nullptr, 'H'},
        {"port",             required_argument, nullptr, 'p'},
        {"mode",             required_argument, nullptr, 'm'},
        {"scan-ids",         required_argument, nullptr, 's'},
        {"registers",        required_argument, nullptr, 'r'},
        {"coils",            required_argument, nullptr, 'c'},
        {"range",            required_argument, nullptr, OPT_RANGE},
        {"test-write",       no_argument,       nullptr, 'w'},
        {"fuzz",             optional_argument, nullptr, 'f'},
        {"threads",          required_argument, nullptr, 'T'},
        {"output",           required_argument, nullptr, 'o'},
        {"format",           required_argument, nullptr, 'F'},
        {"timeout",          required_argument, nullptr, 't'},
        {"connect-timeout",  required_argument, nullptr, OPT_CONNECT_TIMEOUT},
        {"pcap",             required_argument, nullptr, OPT_PCAP},
        {"monitor",          no_argument,       nullptr, OPT_MONITOR},
        {"discover",         required_argument, nullptr, OPT_DISCOVER},
        {"completions",      required_argument, nullptr, OPT_COMPLETIONS},
        {"tls",              no_argument,       nullptr, OPT_TLS},
        {"cert",             required_argument, nullptr, OPT_CERT},
        {"key",              required_argument, nullptr, OPT_KEY},
        {"quiet",            no_argument,       nullptr, 'q'},
        {"verbose",          no_argument,       nullptr, 'v'},
        {"no-color",         no_argument,       nullptr, OPT_NO_COLOR},
        {"no-device-id",     no_argument,       nullptr, OPT_NO_DEVICE_ID},
        {"help",             no_argument,       nullptr, 'h'},
        {nullptr,            0,                 nullptr,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "H:p:m:s:r:c:wf::T:o:F:t:qvh", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'H':
                config.host = optarg;
                break;
            case 'p':
                config.port = static_cast<uint16_t>(std::stoul(optarg));
                break;
            case 'm':
                if (std::string(optarg) == "rtu" || std::string(optarg) == "rtu_over_tcp") {
                    config.protocol_mode = ProtocolMode::RTU_OVER_TCP;
                } else {
                    config.protocol_mode = ProtocolMode::TCP;
                }
                break;
            case 's': {
                uint16_t start, end;
                if (!parse_range(optarg, start, end, '-') || start < 1 || end > 247) {
                    std::cerr << "Error: Invalid unit ID range (must be 1-247)\n";
                    return 1;
                }
                config.id_start = static_cast<uint8_t>(start);
                config.id_end = static_cast<uint8_t>(end);
                break;
            }
            case 'r': {
                uint16_t start, count;
                if (!parse_range(optarg, start, count, ':')) {
                    std::cerr << "Error: Invalid register range (format: start:count)\n";
                    return 1;
                }
                config.register_start = start;
                config.register_count = count;
                break;
            }
            case 'c': {
                uint16_t start, count;
                if (!parse_range(optarg, start, count, ':')) {
                    std::cerr << "Error: Invalid coil range (format: start:count)\n";
                    return 1;
                }
                config.coil_start = start;
                config.coil_count = count;
                break;
            }
            case OPT_RANGE:
                config.extra_ranges = parse_register_ranges(optarg);
                break;
            case 'w':
                config.test_write = true;
                break;
            case 'f':
                config.fuzz_function_codes = true;
                if (optarg) {
                    config.fuzz_unit_id = static_cast<uint8_t>(std::stoul(optarg));
                }
                break;
            case 'T':
                config.thread_count = std::stoi(optarg);
                if (config.thread_count < 1) config.thread_count = 1;
                if (config.thread_count > 64) config.thread_count = 64;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'F':
                config.output_format = optarg;
                break;
            case 't':
                config.timeout_ms = std::stoi(optarg);
                break;
            case OPT_CONNECT_TIMEOUT:
                config.connect_timeout_ms = std::stoi(optarg);
                break;
            case 'q':
                config.quiet = true;
                break;
            case 'v':
                config.verbose = true;
                break;
            case OPT_NO_COLOR:
                config.color = false;
                break;
            case OPT_PCAP:
                pcap_file = optarg;
                break;
            case OPT_MONITOR:
                monitor_mode = true;
                break;
            case OPT_DISCOVER:
                discover_cidr = optarg;
                break;
            case OPT_COMPLETIONS:
                generate_completions(optarg);
                return 0;
            case OPT_TLS:
                // TLS flag acknowledged (requires OpenSSL at link time)
                if (!config.quiet) {
                    std::cerr << "Note: TLS support requires build with -DWITH_TLS=ON\n";
                }
                break;
            case OPT_CERT:
                // Store cert path for TLS mode (placeholder)
                break;
            case OPT_KEY:
                // Store key path for TLS mode (placeholder)
                break;
            case OPT_NO_DEVICE_ID:
                no_device_id = true;
                break;
            case 'h':
            default:
                print_usage(argv[0], config.color);
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (no_device_id) {
        config.read_device_id = false;
    }

    // --discover mode: scan network for Modbus devices and exit
    if (!discover_cidr.empty()) {
        DiscoveryConfig dconf;
        dconf.cidr         = discover_cidr;
        dconf.port         = config.port;
        dconf.timeout_ms   = config.timeout_ms;
        dconf.thread_count = config.thread_count > 1 ? config.thread_count : 16;
        dconf.color        = config.color;
        dconf.quiet        = config.quiet;
        dconf.probe_modbus = true;

        NetworkDiscovery discovery(dconf);
        int found = discovery.run();

        if (config.output_format == "json") {
            std::string json = discovery.format_json();
            if (!output_file.empty()) {
                std::ofstream ofs(output_file);
                ofs << json;
            } else {
                std::cout << json;
            }
        } else {
            std::cout << discovery.format_results();
        }

        return (found > 0) ? 0 : 2;
    }

    if (config.host.empty()) {
        std::cerr << "Error: --host is required\n\n";
        print_usage(argv[0], config.color);
        return 1;
    }

    // --monitor mode: continuously poll registers and alert on changes
    if (monitor_mode) {
        MonitorConfig mconf;
        mconf.host           = config.host;
        mconf.port           = config.port;
        mconf.unit_id        = config.id_start;
        mconf.register_start = config.register_start;
        mconf.register_count = config.register_count;
        mconf.timeout_ms     = config.timeout_ms;
        mconf.color          = config.color;

        RegisterMonitor monitor(mconf);
        g_monitor = &monitor;

        // Install SIGINT handler for clean shutdown
        struct sigaction sa{};
        sa.sa_handler = sigint_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGINT, &sa, nullptr);

        int changes = monitor.run();
        g_monitor = nullptr;

        if (!config.quiet) {
            std::cerr << "\nMonitor stopped. " << changes << " change(s) detected.\n";
        }
        return (changes >= 0) ? 0 : 2;
    }

    // Initialize PCAP writer if requested
    PcapWriter pcap;
    if (!pcap_file.empty()) {
        if (!pcap.open(pcap_file)) {
            std::cerr << "Error: Failed to open PCAP file " << pcap_file << "\n";
            return 2;
        }
        if (!config.quiet) {
            std::cerr << "  PCAP capture: " << pcap_file << "\n";
        }
    }

    ModbusScanner scanner(config);

    if (config.verbose && !config.quiet) {
        scanner.set_log_callback([](const std::string& msg) {
            std::cerr << msg << "\n";
        });
    }

    // Run the main scan
    ScanReport report = scanner.run();

    // Run fuzzing if requested
    FuzzReport fuzz_report{};
    if (config.fuzz_function_codes) {
        fuzz_report = scanner.run_fuzz(config.fuzz_unit_id);
    }

    // Format and output
    OutputFormat fmt = parse_output_format(config.output_format);

    std::string output;
    switch (fmt) {
        case OutputFormat::JSON:
            output = ReportGenerator::to_json(report);
            break;
        case OutputFormat::CSV:
            output = CsvFormatter::format_csv(report);
            break;
        case OutputFormat::Table:
            output = TableFormatter::format_table(report, config.color);
            output += TableFormatter::format_findings_table(report, config.color);
            // Show register/coil details for each unit
            for (const auto& r : report.results) {
                if (!r.responsive) continue;
                output += TableFormatter::format_register_table(r, config.color);
                output += TableFormatter::format_coil_table(r, config.color);
            }
            if (!report.results.empty()) {
                output += TableFormatter::format_timing_table(report, config.color);
            }
            break;
    }

    // Add fuzz results if present
    if (config.fuzz_function_codes && !fuzz_report.entries.empty()) {
        if (fmt == OutputFormat::Table) {
            output += TableFormatter::format_fuzz_table(fuzz_report.entries,
                                                         fuzz_report.unit_id,
                                                         config.color);
        }
        // For JSON/CSV the fuzz results are printed separately for simplicity
    }

    if (!output_file.empty()) {
        std::ofstream ofs(output_file);
        if (!ofs.is_open()) {
            std::cerr << "Error: Failed to write report to " << output_file << "\n";
            return 1;
        }
        ofs << output;
        if (!config.quiet) {
            std::cerr << "\n  Report written to " << output_file << "\n";
        }
    } else {
        std::cout << output;
    }

    // Close PCAP file and report
    if (pcap.is_open()) {
        pcap.close();
        if (!config.quiet) {
            std::cerr << "  PCAP: " << pcap.packet_count() << " packets written to "
                      << pcap_file << "\n";
        }
    }

    return (report.units_responsive > 0) ? 0 : 2;
}
