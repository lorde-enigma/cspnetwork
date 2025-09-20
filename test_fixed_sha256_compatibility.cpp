#include <iostream>
#include <sstream>
#include <iomanip>
#include <array>
#include <functional>
#include <openssl/evp.h>

std::array<uint8_t, 32> generateHash(uint64_t seed, const std::string& context) {
    std::string input = std::to_string(seed) + ":" + context;
    std::array<uint8_t, 32> hash;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    unsigned int hashLen;
    EVP_DigestFinal_ex(ctx, hash.data(), &hashLen);
    EVP_MD_CTX_free(ctx);
    
    return hash;
}

std::string generateIPv6Address(const std::string& domain) {
    std::hash<std::string> hasher;
    uint64_t baseSeed = hasher("alakasan");
    
    std::string context = "ipv6:" + domain;
    auto hash = generateHash(baseSeed, context);
    
    std::stringstream ss;
    std::string prefix = "2a0e:b107:1ef0:";
    
    int prefixGroups = 3;
    int groupsToAdd = 8 - prefixGroups;
    
    ss << prefix;
    
    for (int group = 0; group < groupsToAdd; ++group) {
        if (group > 0) {
            ss << ":";
        }
        
        int hashOffset = (group * 2) % 32;
        uint16_t segment = (static_cast<uint16_t>(hash[hashOffset]) << 8) | 
                          static_cast<uint16_t>(hash[hashOffset + 1]);
        ss << std::hex << std::setfill('0') << std::setw(4) << segment;
    }
    
    return ss.str();
}

int main() {
    std::hash<std::string> hasher;
    uint64_t seedValue = hasher("alakasan");
    
    std::cout << "String seed: alakasan" << std::endl;
    std::cout << "Hash value: " << seedValue << std::endl;
    
    std::string result = generateIPv6Address("alakasan");
    std::cout << "Generated IPv6: " << result << std::endl;
    std::cout << "Expected IPv6:  2a0e:b107:1ef0:6b2d:1594:ead7:9ef5:3593" << std::endl;
    
    return 0;
}
