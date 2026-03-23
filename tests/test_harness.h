#ifndef MIRAGE_TCP_TEST_HARNESS_H
#define MIRAGE_TCP_TEST_HARNESS_H

#include <functional>
#include <stdexcept>
#include <string>

struct TestCase {
    const char* name;
    std::function<void()> run;
};

inline void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

#endif
