#include "include/infrastructure/ipv6_address_manager.h"
#include <iostream>
#include <functional>
#include <iomanip>

using namespace seeded_vpn::infrastructure;
using namespace seeded_vpn::domain;

std::string addressToString(const IPv6Address& addr) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < addr.size(); i += 2) {
        if (i > 0) ss << ":";
        uint16_t group = (static_cast<uint16_t>(addr[i]) << 8) | static_cast<uint16_t>(addr[i + 1]);
        ss << std::setw(4) << group;
    }
    return ss.str();
}

int main() {
    IPv6AddressManager& manager = IPv6AddressManager::getInstance();
    std::hash<std::string> hasher;
    uint64_t seedValue = hasher("alakasan");
    
    std::cout << "=== CSPNETWORK TEST ===" << std::endl;
    std::cout << "string seed: alakasan" << std::endl;
    std::cout << "hash value: " << seedValue << std::endl;
    
    auto result = manager.seedToAddress(seedValue, "alakasan");
    std::cout << "generated ipv6: " << addressToString(result) << std::endl;
    
    std::cout << "\nother tests:" << std::endl;
    uint64_t testSeed = hasher("test");
    auto testResult = manager.seedToAddress(testSeed, "test");
    std::cout << "seed 'test' -> " << addressToString(testResult) << std::endl;
    
    uint64_t exampleSeed = hasher("example.com");
    auto exampleResult = manager.seedToAddress(exampleSeed, "example.com");
    std::cout << "seed 'example.com' -> " << addressToString(exampleResult) << std::endl;
    
    return 0;
}
