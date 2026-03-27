# Changelog

All notable changes to modbus-probe are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [2.2.0] - 2026-04-03
### Added
- Modbus/TCP Secure (TLS) connection support with --tls and --cert/--key flags
- PCAP export of Modbus traffic for Wireshark analysis (--pcap FILE)
- Register change monitoring mode (--monitor) — continuously poll and alert on value changes
- Coil state diff — compare coil states between two scans
- JSON Schema validation for output files
- Bash/Zsh completion script generation (--completions)
### Changed
- Improved RTU CRC performance with lookup table (4x faster)
- Better timeout handling with exponential backoff on retries
- Register dump now shows both hex and decimal values
### Fixed
- CRC16 calculation for edge case with 0xFF bytes
- Thread pool cleanup on SIGINT
- JSON escaping for special characters in device identification strings

## [2.1.0] - 2026-03-15
### Added
- Nmap-style host discovery (--discover CIDR) to find Modbus devices on network
- Register diff mode (--diff) comparing two JSON scan results
- Configurable retry count per unit ID (--retries N)
- Machine-readable exit codes (0=clean, 1=findings, 2=error)
### Changed
- Default timeout increased from 1s to 2s for reliability
- Progress bar now shows ETA
### Fixed
- Segfault when scanning large register ranges (>10000)
- Memory leak in multi-threaded scanning mode

## [2.0.0] - 2026-02-28
### Added
- Modbus RTU over TCP support
- Multi-threaded scanning with configurable thread pool
- Function code fuzzing (FC 1-127)
- Device identification via FC43 MEI
- ASCII table output format
- CSV export
- Colored terminal output with progress bar
- Finding severity classification (CRITICAL/HIGH/MEDIUM/INFO)
### Changed
- Complete CLI rewrite with expanded options
- JSON output schema v2 with device_identification and findings
### Breaking
- CLI arguments reorganized, some flags renamed

## [1.0.0] - 2026-01-20
### Added
- Stable release
- Write permission testing with safe rollback
- Exception response parsing and reporting
- Register data extraction for FC03 and FC04
- Coil reading (FC01)
- JSON report generation with timestamps and summary
### Changed
- Improved connection handling with proper DNS resolution
### Fixed
- Big-endian encoding issues on ARM platforms

## [0.1.0] - 2025-12-10
### Added
- Initial release
- Modbus TCP connection and scanning
- Unit ID enumeration (1-247)
- Read holding registers (FC03)
- Basic JSON output
- CLI with --host, --port, --scan-ids, --output
