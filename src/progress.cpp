#include "progress.h"

#include <cstdio>
#include <iostream>
#include <sstream>

namespace modbus_probe {

TerminalUI::TerminalUI(bool color_enabled, bool quiet)
    : color_enabled_(color_enabled), quiet_(quiet) {}

void TerminalUI::print_banner() const {
    if (quiet_) return;

    const char* c  = color_enabled_ ? ansi::CYAN : "";
    const char* b  = color_enabled_ ? ansi::BOLD : "";
    const char* d  = color_enabled_ ? ansi::DIM  : "";
    const char* r  = color_enabled_ ? ansi::RESET : "";

    std::fprintf(stderr, "\n");
    std::fprintf(stderr, "%s%s", c, b);
    std::fprintf(stderr, "  __  __           _ _                                _          \n");
    std::fprintf(stderr, " |  \\/  | ___   __| | |__  _   _ ___       _ __  _ __| |__   ___ \n");
    std::fprintf(stderr, " | |\\/| |/ _ \\ / _` | '_ \\| | | / __|____| '_ \\| '__| '_ \\ / _ \\\n");
    std::fprintf(stderr, " | |  | | (_) | (_| | |_) | |_| \\__ \\____| |_) | |  | |_) |  __/\n");
    std::fprintf(stderr, " |_|  |_|\\___/ \\__,_|_.__/ \\__,_|___/    | .__/|_|  |_.__/ \\___|\n");
    std::fprintf(stderr, "                                          |_|                     \n");
    std::fprintf(stderr, "%s", r);
    std::fprintf(stderr, "%s  Modbus TCP/RTU Security Scanner v2.0.0%s\n", d, r);
    std::fprintf(stderr, "%s  Copyright (c) 2026 isecwire GmbH -- https://isecwire.com%s\n", d, r);
    std::fprintf(stderr, "\n");
}

std::string TerminalUI::severity_color(Severity sev) const {
    if (!color_enabled_) return "";
    switch (sev) {
        case Severity::INFO:     return ansi::CYAN;
        case Severity::PASS:     return ansi::GREEN;
        case Severity::WARN:     return ansi::YELLOW;
        case Severity::FAIL:     return ansi::RED;
        case Severity::CRITICAL: return std::string(ansi::BOLD) + ansi::RED;
    }
    return "";
}

std::string TerminalUI::severity_tag(Severity sev) const {
    const char* r = color_enabled_ ? ansi::RESET : "";
    std::string color = severity_color(sev);
    switch (sev) {
        case Severity::INFO:     return color + "[INFO]" + r;
        case Severity::PASS:     return color + "[PASS]" + r;
        case Severity::WARN:     return color + "[WARN]" + r;
        case Severity::FAIL:     return color + "[FAIL]" + r;
        case Severity::CRITICAL: return color + "[CRIT]" + r;
    }
    return "[????]";
}

void TerminalUI::print_status(Severity sev, const std::string& message) const {
    if (quiet_) return;
    std::fprintf(stderr, "  %s %s\n", severity_tag(sev).c_str(), message.c_str());
}

void TerminalUI::print_progress(uint32_t current, uint32_t total,
                                 const std::string& label) const {
    if (quiet_) return;
    if (total == 0) return;

    const int bar_width = 30;
    float ratio = static_cast<float>(current) / static_cast<float>(total);
    int filled = static_cast<int>(ratio * bar_width);

    std::string bar;
    bar.reserve(bar_width);
    for (int i = 0; i < bar_width; ++i) {
        if (i < filled) bar += '=';
        else if (i == filled) bar += '>';
        else bar += ' ';
    }

    int pct = static_cast<int>(ratio * 100.0f);
    if (pct > 100) pct = 100;

    std::string lbl = label.empty() ? "" : label + " ";
    const char* c = color_enabled_ ? ansi::CYAN : "";
    const char* r = color_enabled_ ? ansi::RESET : "";

    std::fprintf(stderr, "\r  %s[%s]%s %s%u/%u (%d%%)",
                 c, bar.c_str(), r, lbl.c_str(), current, total, pct);

    if (current >= total) {
        std::fprintf(stderr, "\n");
    }
    std::fflush(stderr);
}

void TerminalUI::clear_line() const {
    if (quiet_) return;
    std::fprintf(stderr, "\r\033[K");
}

std::string TerminalUI::colorize(const std::string& text, const char* color) const {
    if (!color_enabled_) return text;
    return std::string(color) + text + ansi::RESET;
}

void TerminalUI::print_section(const std::string& title) const {
    if (quiet_) return;
    const char* b = color_enabled_ ? ansi::BOLD : "";
    const char* r = color_enabled_ ? ansi::RESET : "";
    std::fprintf(stderr, "\n  %s--- %s ---%s\n\n", b, title.c_str(), r);
}

}  // namespace modbus_probe
