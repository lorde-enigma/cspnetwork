#include "include/infrastructure/ipv6_address_manager.h"
#include "include/domain/types.h"
#include <iostream>
#include <iomanip>

using namespace seeded_vpn::infrastructure;
using namespace seeded_vpn::domain;

int main() {
    try {
        auto& manager = IPv6AddressManager::getInstance();
        
        uint64_t test_seed = 123456789;
        std::string test_domain = "test.example.com";
        
        auto ipv6_addr = manager.seedToAddress(test_seed, test_domain);
        
        std::cout << "Generated IPv6 address for seed " << test_seed 
                  << " and domain " << test_domain << ":\n";
        std::cout << ipv6_addr << std::endl;
        
        uint64_t test_seed2 = 987654321;
        std::string test_domain2 = "google.com";
        
        auto ipv6_addr2 = manager.seedToAddress(test_seed2, test_domain2);
        
        std::cout << "Generated IPv6 address for seed " << test_seed2 
                  << " and domain " << test_domain2 << ":\n";
        std::cout << ipv6_addr2 << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
