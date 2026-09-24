#include "vphone/backend.hpp"

#include <iostream>
#include <string>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__ << ": " #expr "\n"; \
            return 1; \
        } \
    } while (0)

int main() {
    CHECK(std::string(vphone::to_string(vphone::CapabilityState::supported)) == "supported");
    CHECK(std::string(vphone::to_string(vphone::CapabilityState::unsupported)) == "unsupported");
    CHECK(std::string(vphone::to_string(vphone::CapabilityState::unknown)) == "unknown");
    return 0;
}
