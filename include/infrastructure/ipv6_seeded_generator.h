#pragma once

#include "../domain/entities.h"
#include <string>
#include <array>
#include <random>

namespace seeded_vpn::infrastructure {

class IPv6SeededGenerator {
public:
    explicit IPv6SeededGenerator(domain::SeedValue seed);
    
    std::string generateUniqueLocal();
    std::string generateLinkLocal();
    std::string generateGlobal();
    std::array<uint8_t, 16> generateRawAddress(const std::string& prefix);
    
    static bool isValidIPv6(const std::string& address);

private:
    std::string formatIPv6(const std::array<uint8_t, 16>& bytes);
    void seedRng(const std::string& context) const;
    std::array<uint8_t, 16> generateWithPrefix(const std::array<uint8_t, 16>& prefix, size_t prefixLen);
    
    domain::SeedValue seed_;
    mutable std::mt19937_64 rng_;
};

}
