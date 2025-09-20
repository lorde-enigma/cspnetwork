#include "src/infrastructure/ipv6_address_manager.cpp"
#include <iostream>
#include <functional>

int main() {
    seeded_vpn::infrastructure::IPv6AddressManager manager("alakasan");
    
    std::hash<std::string> hasher;
    uint64_t numeric_seed = hasher("alakasan");
    
    std::cout << "string seed: alakasan" << std::endl;
    std::cout << "numeric seed: " << numeric_seed << std::endl;
    
    seeded_vpn::domain::IPv6Address result = manager.seedToAddress(numeric_seed);
    
    std::cout << "generated ipv6: ";
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < result.size(); i += 2) {
        if (i > 0) std::cout << ":";
        std::cout << std::setw(2) << static_cast<int>(result[i])
                  << std::setw(2) << static_cast<int>(result[i + 1]);
    }
    std::cout << std::dec << std::endl;
    
    std::cout << "expected from cipherproxy: 2a0e:b107:1ef0:cdac:32d9:7b09:7231:e7fa" << std::endl;
    
    return 0;
}
