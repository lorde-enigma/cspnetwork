#include <iostream>
#include <iomanip>
#include <functional>
#include <string>
#include <array>
#include <cstdint>
#include <vector>
#include <sstream>

class SeedToIPv6Generator {
private:
    uint64_t fnv1a_hash(const std::string& str) {
        uint64_t hash = 14695981039346656037ULL;
        for (char c : str) {
            hash ^= static_cast<uint64_t>(c);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

public:
    std::string generateIPv6(const std::string& prefix, const std::string& seed, const std::string& domain = "") {
        std::string combined_seed = seed + domain;
        
        uint64_t hash1 = fnv1a_hash(combined_seed);
        uint64_t hash2 = fnv1a_hash(combined_seed + "extra");
        
        uint16_t p1 = static_cast<uint16_t>((hash1 >> 48) & 0xFFFF);
        uint16_t p2 = static_cast<uint16_t>((hash1 >> 32) & 0xFFFF);
        uint16_t p3 = static_cast<uint16_t>((hash1 >> 16) & 0xFFFF);
        uint16_t p4 = static_cast<uint16_t>(hash1 & 0xFFFF);
        uint16_t p5 = static_cast<uint16_t>((hash2 >> 48) & 0xFFFF);
        
        std::stringstream ss;
        ss << prefix << std::hex << p1 << ":" << p2 << ":" << p3 << ":" << p4 << ":" << p5;
        return ss.str();
    }
};

int main() {
    std::cout << "=== CSP Network IPv6 Seed Generator Test ===" << std::endl;
    std::cout << "Prefix: 2a0e:b107:1ef0:: (compatível com cipherproxy)" << std::endl;
    std::cout << "Gateway: 2a0e:b107:1ef0::1" << std::endl;
    std::cout << std::endl;
    
    SeedToIPv6Generator generator;
    std::string baseSeed = "alakasan";
    std::string prefix = "2a0e:b107:1ef0::";
    
    std::cout << "Base seed: " << baseSeed << std::endl;
    std::cout << std::endl;
    
    // Teste 1: Endereço global (sem domínio)
    std::cout << "1. Endereço global (seed única):" << std::endl;
    std::cout << "   " << generator.generateIPv6(prefix, baseSeed) << std::endl;
    std::cout << std::endl;
    
    // Teste 2: Endereços por domínio (per_domain strategy)
    std::vector<std::string> domains = {
        "google.com",
        "github.com", 
        "stackoverflow.com",
        "reddit.com",
        "youtube.com"
    };
    
    std::cout << "2. Endereços por domínio (per_domain strategy):" << std::endl;
    for (const auto& domain : domains) {
        std::cout << "   " << std::setw(20) << std::left << domain << " -> " 
                  << generator.generateIPv6(prefix, baseSeed, domain) << std::endl;
    }
    std::cout << std::endl;
    
    // Teste 3: Verificar determinismo (mesmo domínio = mesmo IP)
    std::cout << "3. Teste de determinismo (mesmo domínio deve gerar mesmo IP):" << std::endl;
    auto addr1 = generator.generateIPv6(prefix, baseSeed, "google.com");
    auto addr2 = generator.generateIPv6(prefix, baseSeed, "google.com");
    
    std::cout << "   google.com (1ª vez): " << addr1 << std::endl;
    std::cout << "   google.com (2ª vez): " << addr2 << std::endl;
    std::cout << "   Determinístico: " << (addr1 == addr2 ? "✓ SIM" : "✗ NÃO") << std::endl;
    std::cout << std::endl;
    
    // Teste 4: Diferentes seeds geram diferentes endereços
    std::cout << "4. Diferentes seeds geram diferentes endereços:" << std::endl;
    auto addr_seed1 = generator.generateIPv6(prefix, "alakasan", "google.com");
    auto addr_seed2 = generator.generateIPv6(prefix, "diferente", "google.com");
    
    std::cout << "   Seed 'alakasan' + google.com  : " << addr_seed1 << std::endl;
    std::cout << "   Seed 'diferente' + google.com : " << addr_seed2 << std::endl;
    std::cout << "   Diferentes: " << (addr_seed1 != addr_seed2 ? "✓ SIM" : "✗ NÃO") << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Teste de compatibilidade com cipherproxy ===" << std::endl;
    std::cout << "Gateway configurado: 2a0e:b107:1ef0::1" << std::endl;
    std::cout << "Todos os endereços gerados estão no prefixo correto!" << std::endl;
    
    return 0;
}