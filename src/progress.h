#pragma once
// ---------------------------------------------------------------------------
// progress.h -- Terminal progress display with ANSI color support
//
// Provides progress bars, colored output helpers, and an ASCII art banner
// for polished CLI presentation.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>

namespace modbus_probe {

// ANSI color codes
namespace ansi {
    constexpr const char* RESET   = "\033[0m";
    constexpr const char* BOLD    = "\033[1m";
    constexpr const char* DIM     = "\033[2m";

    constexpr const char* RED     = "\033[31m";
    constexpr const char* GREEN   = "\033[32m";
    constexpr const char* YELLOW  = "\033[33m";
    constexpr const char* BLUE    = "\033[34m";
    constexpr const char* MAGENTA = "\033[35m";
    constexpr const char* CYAN    = "\033[36m";
    constexpr const char* WHITE   = "\033[37m";

    constexpr const char* BG_RED    = "\033[41m";
    constexpr const char* BG_GREEN  = "\033[42m";
    constexpr const char* BG_YELLOW = "\033[43m";
}

// Severity levels for colored output
enum class Severity {
    INFO,
    PASS,
    WARN,
    FAIL,
    CRITICAL,
};

class TerminalUI {
public:
    explicit TerminalUI(bool color_enabled = true, bool quiet = false);

    // Print the startup ASCII art banner
    void print_banner() const;

    // Print a severity-tagged message: [INFO] ..., [PASS] ..., [FAIL] ..., etc.
    void print_status(Severity sev, const std::string& message) const;

    // Print a progress bar:  [========>          ] 42/100 (42%)
    void print_progress(uint32_t current, uint32_t total,
                        const std::string& label = "") const;

    // Clear the current line (for progress bar updates)
    void clear_line() const;

    // Severity label helpers
    std::string severity_tag(Severity sev) const;
    std::string severity_color(Severity sev) const;

    // Colorize a string
    std::string colorize(const std::string& text, const char* color) const;

    // Section header (bold separator line)
    void print_section(const std::string& title) const;

    bool is_color_enabled() const { return color_enabled_; }
    bool is_quiet() const { return quiet_; }

private:
    bool color_enabled_;
    bool quiet_;
};

}  // namespace modbus_probe
