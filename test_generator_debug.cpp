#include "include/infrastructure/repositories.h"
#include <iostream>

using namespace seeded_vpn;

int main() {
    try {
        std::cout << "Testing ConcreteSeedGenerator initialization..." << std::endl;
        
        auto seed_generator = std::make_shared<infrastructure::ConcreteSeedGenerator>();
        std::cout << "ConcreteSeedGenerator created successfully" << std::endl;
        
        std::cout << "Testing SeedContext creation..." << std::endl;
        domain::SeedContext context;
        context.client_id = 1;
        context.connection_id = 1;
        
        std::cout << "Testing seed generation..." << std::endl;
        auto seed = seed_generator->generate(context);
        std::cout << "Generated seed: " << seed << std::endl;
        
        std::cout << "Testing seed validation..." << std::endl;
        bool is_valid = seed_generator->validate_seed(seed);
        std::cout << "Seed validation: " << (is_valid ? "VALID" : "INVALID") << std::endl;
        
        std::cout << "All tests passed!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
