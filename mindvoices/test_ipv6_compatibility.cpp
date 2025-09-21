#include <iostream>
#include <string>
#include <array>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/sha.h>

std::string to_hex_string(const std::array<uint8_t, 16>& data) {
    std::ostringstream oss;
    for (size_t i = 0; i < data.size(); i += 2) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i]
            << std::setw(2) << (int)data[i+1];
    }
    return oss.str();
}

std::array<uint8_t, 16> generate_ipv6_cspnetwork(uint64_t seed, const std::string& domain) {
    std::string input = std::to_string(seed) + ":ipv6:" + domain;
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    
    std::array<uint8_t, 16> ipv6_address;
    ipv6_address[0] = 0x2a;
    ipv6_address[1] = 0x0e;
    ipv6_address[2] = 0xb1;
    ipv6_address[3] = 0x07;
    ipv6_address[4] = 0x1e;
    ipv6_address[5] = 0xf0;
    
    for (int i = 0; i < 10; ++i) {
        ipv6_address[6 + i] = hash[i];
    }
    
    return ipv6_address;
}

std::array<uint8_t, 16> generate_ipv6_cipherproxy(uint64_t seed, const std::string& domain) {
    std::string input = std::to_string(seed) + ":ipv6:" + domain;
    
    std::array<uint8_t, 32> hash;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    unsigned int hashLen;
    EVP_DigestFinal_ex(ctx, hash.data(), &hashLen);
    EVP_MD_CTX_free(ctx);
    
    std::array<uint8_t, 16> addr;
    addr[0] = 0x2a;
    addr[1] = 0x0e;
    addr[2] = 0xb1;
    addr[3] = 0x07;
    addr[4] = 0x1e;
    addr[5] = 0xf0;
    
    for (int i = 6; i < 16; i++) {
        addr[i] = hash[i - 6];
    }
    
    return addr;
}

int main() {
    struct TestCase {
        uint64_t seed;
        std::string domain;
        std::string description;
    };
    
    TestCase tests[] = {
        {987654321ULL, "test_client_123-20250921-002744-4052", "Teste 1"},
        {123456789ULL, "test_client_456-20250921-002751-2285", "Teste 2"},
        {555666777ULL, "example.com", "Teste 3"},
        {888999000ULL, "mydomain.test", "Teste 4"}
    };
    
    std::cout << "=== Teste de Compatibilidade IPv6 ===" << std::endl;
    std::cout << std::endl;
    
    for (const auto& test : tests) {
        std::cout << test.description << " - Seed: " << test.seed 
                  << ", Domain: " << test.domain << std::endl;
        
        auto cspnetwork_ipv6 = generate_ipv6_cspnetwork(test.seed, test.domain);
        auto cipherproxy_ipv6 = generate_ipv6_cipherproxy(test.seed, test.domain);
        
        std::cout << "  cspnetwork:  " << to_hex_string(cspnetwork_ipv6) << std::endl;
        std::cout << "  cipherproxy: " << to_hex_string(cipherproxy_ipv6) << std::endl;
        
        bool match = (cspnetwork_ipv6 == cipherproxy_ipv6);
        std::cout << "  Resultado:   " << (match ? "MATCH ✓" : "DIFERENTE ✗") << std::endl;
        std::cout << std::endl;
    }
    
    return 0;
}
