#include "vphone/backend.hpp"
#include <cassert>
#include <string>

int main() {
    assert(std::string(vphone::to_string(vphone::CapabilityState::supported)) == "supported");
    assert(std::string(vphone::to_string(vphone::CapabilityState::unsupported)) == "unsupported");
    assert(std::string(vphone::to_string(vphone::CapabilityState::unknown)) == "unknown");
    return 0;
}
