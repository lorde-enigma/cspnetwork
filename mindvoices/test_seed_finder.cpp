#include <iostream>
#include <sstream>
#include <iomanip>
#include <array>
#include <functional>
#include <vector>
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

std::string generateIPv6Address(uint64_t baseSeed, const std::string& domain) {
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
    std::string expected = "2a0e:b107:1ef0:6b2d:1594:ead7:9ef5:3593";
    
    std::cout << "Testing different seed values to find the match:" << std::endl;
    std::cout << "Expected: " << expected << std::endl << std::endl;
    
    // Test different seed values
    for (uint64_t seed = 0; seed < 100; ++seed) {
        std::string result = generateIPv6Address(seed, "alakasan");
        if (result == expected) {
            std::cout << "FOUND MATCH! Seed: " << seed << std::endl;
            std::cout << "Generated: " << result << std::endl;
            return 0;
        }
    }
    
    // Test some common hash values
    std::hash<std::string> hasher;
    uint64_t stringHash = hasher("alakasan");
    std::cout << "Testing std::hash result: " << stringHash << std::endl;
    std::string result = generateIPv6Address(stringHash, "alakasan");
    std::cout << "Generated: " << result << std::endl;
    
    // Test direct string conversion
    uint64_t directConversion = std::stoull("alakasan", nullptr, 36);
    std::cout << "Testing base36 conversion: " << directConversion << std::endl;
    result = generateIPv6Address(directConversion, "alakasan");
    std::cout << "Generated: " << result << std::endl;
    
    // Test simple number values
    std::cout << "Testing simple values:" << std::endl;
    std::vector<uint64_t> testSeeds = {12345ULL, 42ULL, 1337ULL, 0xABCULL, 0xDEADBEEFULL};
    for (uint64_t seed : testSeeds) {
        result = generateIPv6Address(seed, "alakasan");
        std::cout << "Seed " << seed << ": " << result << std::endl;
    }
    
    return 0;
}
