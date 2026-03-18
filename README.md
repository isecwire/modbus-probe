# modbus-probe

Modbus TCP/RTU security scanner and auditor for OT/SCADA environments.

`modbus-probe` performs unauthenticated reconnaissance, device fingerprinting, function code fuzzing, and write-access testing against Modbus devices. It implements the Modbus TCP and RTU-over-TCP protocols from scratch using raw sockets -- no external Modbus library dependencies -- giving full control over frame construction and timing for security assessment purposes.

![modbus-probe screenshot](assets/screenshot.svg)

## Features

- **Unit ID enumeration** -- scan all 247 valid Modbus unit IDs to discover responsive devices behind gateways
- **Full function code support** -- FC01 (Read Coils), FC02 (Read Discrete Inputs), FC03 (Read Holding Registers), FC04 (Read Input Registers), FC05 (Write Single Coil), FC06 (Write Single Register), FC15 (Write Multiple Coils), FC16 (Write Multiple Registers), FC43/14 (Read Device Identification)
- **Modbus RTU-over-TCP** -- native support for RTU framing with CRC-16/Modbus (optimized with lookup table), common with serial-to-Ethernet gateways
- **Device fingerprinting** -- extract vendor name, product code, revision, and model via FC43 MEI (Read Device Identification)
- **Function code fuzzing** -- send all function codes 1-127 and report which are supported, with response timing
- **Network discovery** -- scan IP ranges (CIDR notation) for hosts with open Modbus TCP ports using `--discover`
- **Register change monitoring** -- continuously poll registers and alert on value changes with colored diff output using `--monitor`
- **PCAP traffic capture** -- export all Modbus TCP frames to PCAP format for Wireshark analysis with `--pcap`
- **Register range scanning** -- scan large register ranges with automatic chunking (125 registers per request)
- **Unauthorized write testing** -- safely test whether a device accepts unauthenticated write operations (FC06) with automatic rollback to the original value
- **Multi-threaded scanning** -- configurable thread pool for parallel unit ID enumeration
- **Response timing analysis** -- measure and report per-operation latencies for each unit ID
- **Severity classification** -- automatic finding classification (CRITICAL, HIGH, MEDIUM, INFO)
- **Multiple output formats** -- JSON, CSV, and formatted ASCII tables with Unicode box drawing
- **Colored terminal output** -- ANSI-colored status indicators with progress bars
- **Shell completions** -- generate Bash/Zsh completion scripts with `--completions`
- **Zero external dependencies** -- pure C++17 with POSIX sockets and pthreads; builds anywhere with a modern compiler

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

The binary is produced at `build/modbus-probe`.

### Running Tests

```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
./modbus-probe-tests
```

### Requirements

- C++17 compiler (GCC 7+, Clang 5+)
- CMake 3.14+
- Linux/macOS (POSIX sockets + pthreads)

## Usage

```
modbus-probe [options]

Required:
  -H, --host <addr>       Target host (IP or hostname)

Connection:
  -p, --port <port>       Modbus TCP port (default: 502)
  -m, --mode <mode>       Protocol mode: tcp, rtu (default: tcp)
  -t, --timeout <ms>      Response timeout in ms (default: 2000)
      --connect-timeout    Connection timeout in ms (default: 3000)

Scanning:
  -s, --scan-ids <range>  Unit ID range to scan, e.g. 1-247 (default: 1-247)
  -r, --registers <range> Register start and count, e.g. 0:10 (default: 0:10)
  -c, --coils <range>     Coil start and count, e.g. 0:16 (default: 0:16)
      --range <ranges>    Extra register ranges, e.g. 0-100,400-500
  -w, --test-write        Test for unauthorized write access (with rollback)
      --no-device-id      Skip FC43/14 device identification

Fuzzing:
  -f, --fuzz [unit_id]    Fuzz all function codes (1-127) on unit ID

Discovery & Monitoring:
      --discover <CIDR>   Scan IP range for Modbus devices (e.g. 192.168.1.0/24)
      --monitor           Monitor registers for changes (Ctrl+C to stop)

Performance:
  -T, --threads <N>       Number of scanning threads (default: 1)

Output:
  -o, --output <file>     Write report to file
  -F, --format <fmt>      Output format: json, csv, table (default: json)
      --pcap <file>       Capture Modbus traffic to PCAP file
  -q, --quiet             Suppress progress, only emit report data
  -v, --verbose           Verbose output with per-operation details
      --no-color          Disable colored terminal output
      --completions <sh>  Generate shell completions (bash, zsh)
  -h, --help              Show this help message
```

### Examples

Basic scan of a PLC on the default Modbus TCP port:

```bash
modbus-probe --host 192.168.1.100
```

Scan unit IDs 1-10 with write testing, 4 threads, ASCII table output:

```bash
modbus-probe -H 10.0.0.50 -s 1-10 -w -T 4 -F table
```

RTU-over-TCP scan with extended register range:

```bash
modbus-probe -H plc.local -m rtu --range 0-100,400-500
```

Fuzz all function codes on unit ID 1:

```bash
modbus-probe -H 10.0.0.50 --fuzz 1
```

Quick scan with JSON to file:

```bash
modbus-probe -H plc.local -s 1-5 -q -o report.json
```

CSV export for spreadsheet analysis:

```bash
modbus-probe -H 192.168.1.100 -F csv -o findings.csv
```

Scan specific register ranges across multiple units:

```bash
modbus-probe -H 10.0.0.50 -s 1-5 --range 0-99,400-499,1000-1099
```

Verbose scan with device identification disabled:

```bash
modbus-probe -H 192.168.1.100 -v --no-device-id
```

Discover Modbus devices on a /24 subnet:

```bash
modbus-probe --discover 192.168.1.0/24 -T 32
```

Monitor register changes in real time:

```bash
modbus-probe -H 192.168.1.100 -s 1 -r 0:20 --monitor
```

Capture traffic to PCAP while scanning:

```bash
modbus-probe -H 10.0.0.50 -s 1-10 --pcap capture.pcap
```

Generate Bash completions:

```bash
modbus-probe --completions bash > /etc/bash_completion.d/modbus-probe
```

