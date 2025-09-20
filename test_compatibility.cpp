#include <iostream>
#include <string>
#include <array>
#include <iomanip>
#include <sstream>
#include <cstdint>

using IPv6Address = std::array<uint8_t, 16>;

uint64_t fnv1a_hash(const std::string& str) {
    const uint64_t fnv_prime = 1099511628211ULL;
    const uint64_t fnv_offset_basis = 14695981039346656037ULL;
    
    uint64_t hash = fnv_offset_basis;
    for (char c : str) {
        hash ^= static_cast<uint64_t>(c);
        hash *= fnv_prime;
    }
    return hash;
}

IPv6Address generateIPv6(const std::string& seed, const std::string& domain) {
    IPv6Address address{};
    
    address[0] = 0x2a;
    address[1] = 0x0e;
    address[2] = 0xb1;
    address[3] = 0x07;
    address[4] = 0x1e;
    address[5] = 0xf0;
    address[6] = 0x00;
    address[7] = 0x00;
    
    std::string combined = seed + ":" + domain;
    uint64_t hash1 = fnv1a_hash(combined);
    uint64_t hash2 = fnv1a_hash(combined + ":suffix");
    
    address[8] = (hash1 >> 56) & 0xFF;
    address[9] = (hash1 >> 48) & 0xFF;
    address[10] = (hash1 >> 40) & 0xFF;
    address[11] = (hash1 >> 32) & 0xFF;
    address[12] = (hash2 >> 24) & 0xFF;
    address[13] = (hash2 >> 16) & 0xFF;
    address[14] = (hash2 >> 8) & 0xFF;
    address[15] = hash2 & 0xFF;
    
    return address;
}

std::string addressToString(const IPv6Address& addr) {
    std::ostringstream oss;
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t group = (static_cast<uint16_t>(addr[i]) << 8) | addr[i + 1];
        oss << std::hex << group;
    }
    return oss.str();
}

int main() {
    std::string seed = "alakasan";
    std::string domain = "google.com";
    
    std::cout << "test ipv6 algorithm compatibility\n";
    std::cout << "seed: " << seed << "\n";
    std::cout << "domain: " << domain << "\n";
    
    auto addr = generateIPv6(seed, domain);
    std::cout << "generated: " << addressToString(addr) << "\n";
    
    std::cout << "\nexpected from test_seeds: 2a0e:b107:1ef0::a35:5936:f5a:48e3:8494\n";
    
    return 0;
}
