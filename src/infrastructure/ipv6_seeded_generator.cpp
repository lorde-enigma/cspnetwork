#include "../include/infrastructure/ipv6_seeded_generator.h"
#include <sstream>
#include <iomanip>
#include <regex>

namespace seeded_vpn::infrastructure {

IPv6SeededGenerator::IPv6SeededGenerator(domain::SeedValue seed) 
    : seed_(seed), rng_(seed) {}

std::string IPv6SeededGenerator::generateUniqueLocal() {
    std::array<uint8_t, 16> prefix = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    seedRng("unique_local");
    auto address = generateWithPrefix(prefix, 8);
    return formatIPv6(address);
}

std::string IPv6SeededGenerator::generateLinkLocal() {
    std::array<uint8_t, 16> prefix = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    seedRng("link_local");
    auto address = generateWithPrefix(prefix, 10);
    return formatIPv6(address);
}

std::string IPv6SeededGenerator::generateGlobal() {
    std::array<uint8_t, 16> prefix = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    seedRng("global");
    auto address = generateWithPrefix(prefix, 32);
    return formatIPv6(address);
}

std::array<uint8_t, 16> IPv6SeededGenerator::generateRawAddress(const std::string& prefix) {
    seedRng("raw_" + prefix);
    
    std::array<uint8_t, 16> address;
    for (size_t i = 0; i < 16; i += 8) {
        uint64_t chunk = rng_();
        for (int j = 0; j < 8 && (i + j) < 16; ++j) {
            address[i + j] = static_cast<uint8_t>((chunk >> (j * 8)) & 0xFF);
        }
    }
    
    return address;
}

bool IPv6SeededGenerator::isValidIPv6(const std::string& address) {
    std::regex ipv6_pattern(R"(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$)");
    return std::regex_match(address, ipv6_pattern);
}

std::string IPv6SeededGenerator::formatIPv6(const std::array<uint8_t, 16>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t word = (static_cast<uint16_t>(bytes[i]) << 8) | bytes[i + 1];
        oss << std::setw(4) << word;
    }
    
    return oss.str();
}

void IPv6SeededGenerator::seedRng(const std::string& context) const {
    uint64_t baseSeed = seed_;
    std::hash<std::string> hasher;
    uint64_t contextHash = hasher(context);
    uint64_t contextSeed = baseSeed ^ contextHash;
    rng_.seed(contextSeed);
}

std::array<uint8_t, 16> IPv6SeededGenerator::generateWithPrefix(const std::array<uint8_t, 16>& prefix, size_t prefixLen) {
    auto address = prefix;
    
    size_t startByte = prefixLen / 8;
    size_t startBit = prefixLen % 8;
    
    if (startBit != 0) {
        uint8_t mask = (1 << (8 - startBit)) - 1;
        address[startByte] = (address[startByte] & (~mask)) | (static_cast<uint8_t>(rng_()) & mask);
        startByte++;
    }
    
    for (size_t i = startByte; i < 16; i += 8) {
        uint64_t chunk = rng_();
        for (int j = 0; j < 8 && (i + j) < 16; ++j) {
            address[i + j] = static_cast<uint8_t>((chunk >> (j * 8)) & 0xFF);
        }
    }
    
    return address;
}

}
