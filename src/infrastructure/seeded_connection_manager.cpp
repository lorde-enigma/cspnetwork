#include "../include/infrastructure/seeded_connection_manager.h"
#include <iostream>
#include <sstream>

namespace seeded_vpn::infrastructure {

SeededConnectionManager::SeededConnectionManager(const std::string& interface)
    : interface_(interface)
    , ipv6Manager_(IPv6AddressManager::getInstance())
    , seedGenerator_(std::make_unique<SeededGenerator>()) {
}

std::string SeededConnectionManager::allocateIPv6ForClient(domain::SeedValue seed) {
    IPv6SeededGenerator generator(seed);
    std::string ipv6Address = generator.generateUniqueLocal();
    
    auto result = ipv6Manager_.allocateAddress(interface_, ipv6Address);
    
    if (result == IPv6AddressManager::Result::SUCCESS || 
        result == IPv6AddressManager::Result::ALREADY_EXISTS) {
        return ipv6Address;
    }
    
    return "";
}

void SeededConnectionManager::releaseIPv6ForClient(const std::string& ipv6) {
    ipv6Manager_.releaseAddress(interface_, ipv6);
}

bool SeededConnectionManager::isIPv6Available(const std::string& ipv6) {
    return !ipv6Manager_.checkAddressExists(interface_, ipv6);
}

std::vector<std::string> SeededConnectionManager::getActiveAddresses() {
    return ipv6Manager_.listInterfaceAddresses(interface_);
}

void SeededConnectionManager::cleanup() {
    ipv6Manager_->cleanup(interface_);
}

void SeededConnectionManager::setNetworkInterface(const std::string& interface) {
    interface_ = interface;
}

std::string SeededConnectionManager::getNetworkInterface() const {
    return interface_;
}

}
