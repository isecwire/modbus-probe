// Minimal test framework -- no external dependencies
// Provides TEST() macro and ASSERT_* helpers with colored output

#pragma once  // guard for include, but this file is also compiled as main

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace test_fw {

struct TestCase {
    std::string name;
    std::function<void()> func;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct TestRegistrar {
    TestRegistrar(const char* name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline int run_all() {
    int passed = 0, failed = 0;
    for (auto& t : registry()) {
        try {
            t.func();
            std::printf("  \033[32mPASS\033[0m  %s\n", t.name.c_str());
            ++passed;
        } catch (const std::exception& e) {
            std::printf("  \033[31mFAIL\033[0m  %s\n        %s\n", t.name.c_str(), e.what());
            ++failed;
        }
    }
    std::printf("\n%d passed, %d failed, %d total\n", passed, failed, passed + failed);
    return failed > 0 ? 1 : 0;
}

}  // namespace test_fw

#define TEST(name) \
    static void test_##name(); \
    static test_fw::TestRegistrar reg_##name(#name, test_##name); \
    static void test_##name()

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) throw std::runtime_error( \
        std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
        ": ASSERT_TRUE failed: " #expr); } while(0)

#define ASSERT_FALSE(expr) \
    do { if ((expr)) throw std::runtime_error( \
        std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
        ": ASSERT_FALSE failed: " #expr); } while(0)

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) throw std::runtime_error( \
        std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
        ": ASSERT_EQ failed: " #a " != " #b); } while(0)

#define ASSERT_NE(a, b) \
    do { if ((a) == (b)) throw std::runtime_error( \
        std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
        ": ASSERT_NE failed: " #a " == " #b); } while(0)

#define ASSERT_GE(a, b) \
    do { if ((a) < (b)) throw std::runtime_error( \
        std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
        ": ASSERT_GE failed: " #a " < " #b); } while(0)

#define ASSERT_STR_CONTAINS(haystack, needle) \
    do { if (std::string(haystack).find(needle) == std::string::npos) \
        throw std::runtime_error( \
            std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
            ": ASSERT_STR_CONTAINS failed: \"" + std::string(needle) + \
            "\" not found"); } while(0)

// Main entry point -- only define main when compiled as the runner
#ifndef TEST_FRAMEWORK_NO_MAIN
int main() {
    std::printf("Running modbus-probe tests...\n\n");
    return test_fw::run_all();
}
#endif
