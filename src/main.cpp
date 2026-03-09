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
