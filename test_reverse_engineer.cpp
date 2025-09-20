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

uint64_t stringToSeed(const std::string& str) {
    std::hash<std::string> hasher;
    return hasher(str);
}

int main() {
    // The cipherproxy test is generating: 2a0e:b107:1ef0:cdac:32d9:7b09:7231:e7fa
    // This suggests the actual domain being tested might be different or the seed is different
    
    std::string actualGenerated = "2a0e:b107:1ef0:cdac:32d9:7b09:7231:e7fa";
    std::string expectedFromUser = "2a0e:b107:1ef0:6b2d:1594:ead7:9ef5:3593";
    
    std::cout << "From cipherproxy test: " << actualGenerated << std::endl;
    std::cout << "Expected by user:      " << expectedFromUser << std::endl;
    
    // Test the seed from configuration
    uint64_t alakasanSeed = stringToSeed("alakasan");
    std::string testResult = generateIPv6Address(alakasanSeed, "alakasan");
    std::cout << "Using alakasan seed:   " << testResult << std::endl;
    
    // Test if the cipherproxy test uses a different domain
    std::string cipherproxyTest = generateIPv6Address(alakasanSeed, "test.domain");
    std::cout << "Using test.domain:     " << cipherproxyTest << std::endl;
    
    // Check if we can reverse engineer the seed that produces the expected result
    std::cout << std::endl << "Searching for seed that produces the expected result..." << std::endl;
    for (uint64_t seed = 0; seed < 10000; ++seed) {
        std::string result = generateIPv6Address(seed, "alakasan");
        if (result == expectedFromUser) {
            std::cout << "FOUND! Seed " << seed << " produces: " << result << std::endl;
            return 0;
        }
    }
    
    std::cout << "No matching seed found in range 0-9999" << std::endl;
    return 0;
}
