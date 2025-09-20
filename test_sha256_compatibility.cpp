#include <iostream>
#include <iomanip>
#include <string>
#include <array>
#include <openssl/evp.h>

using IPv6Address = std::array<uint8_t, 16>;

IPv6Address generateIPv6Address(const std::string& seed) {
    std::string context = "ipv6:" + seed;
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, context.c_str(), context.length());
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);
    
    std::string prefix = "2a0e:b107:1ef0:";
    int prefixGroups = 0;
    for (char c : prefix) {
        if (c == ':') prefixGroups++;
    }
    int totalGroups = 8;
    int generatedGroups = totalGroups - prefixGroups;
    
    IPv6Address address{};
    
    address[0] = 0x2a;
    address[1] = 0x0e;
    address[2] = 0xb1;
    address[3] = 0x07;
    address[4] = 0x1e;
    address[5] = 0xf0;
    
    int hashOffset = 0;
    for (int i = 0; i < generatedGroups && hashOffset + 1 < static_cast<int>(hashLen); ++i) {
        uint16_t group = (static_cast<uint16_t>(hash[hashOffset]) << 8) | 
                        static_cast<uint16_t>(hash[hashOffset + 1]);
        
        int byteIndex = 6 + (i * 2);
        address[byteIndex] = static_cast<uint8_t>(group >> 8);
        address[byteIndex + 1] = static_cast<uint8_t>(group & 0xFF);
        
        hashOffset += 2;
    }
    
    return address;
}

std::string addressToString(const IPv6Address& address) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < address.size(); i += 2) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<int>(address[i])
            << std::setw(2) << static_cast<int>(address[i + 1]);
    }
    
    return oss.str();
}

int main() {
    std::cout << "testing sha256 ipv6 generation compatibility" << std::endl;
    
    std::string testSeed = "alakasan";
    IPv6Address address = generateIPv6Address(testSeed);
    std::string addrStr = addressToString(address);
    
    std::cout << "seed: " << testSeed << std::endl;
    std::cout << "generated ipv6: " << addrStr << std::endl;
    std::cout << "expected (cipherproxy): 2a0e:b107:1ef0:6b2d:1594:ead7:9ef5:3593" << std::endl;
    
    if (addrStr == "2a0e:b107:1ef0:6b2d:1594:ead7:9ef5:3593") {
        std::cout << "success: algorithms match!" << std::endl;
        return 0;
    } else {
        std::cout << "mismatch: algorithms differ" << std::endl;
        return 1;
    }
}
