#include "testing/test_framework.h"
#include "domain/entities.h"
#include "domain/types.h"
#include "infrastructure/seed_generator.h"
#include <random>

namespace seeded_vpn::testing {

TEST_SUITE(SeedGeneratorTests) {
    SETUP() {
        auto test_generator = std::make_unique<seeded_vpn::infrastructure::CryptoSeedGenerator>();
    }

    TEST_CASE(GenerateSeedBasic, "Test basic seed generation functionality") {
        auto generator = seeded_vpn::infrastructure::CryptoSeedGenerator();
        auto seed = generator.generate_seed();
        
        ASSERT_NOT_NULL(seed);
        ASSERT_TRUE(seed->is_valid());
        ASSERT_GREATER(seed->get_address_pool().size(), 0);
    }

    TEST_CASE(GenerateSeedWithStrategy) {
        auto generator = seeded_vpn::infrastructure::SeedGenerator();
        auto seed = generator.generate_seed(seeded_vpn::domain::SeedAllocationStrategy::PER_CONNECTION);
        
        ASSERT_NOT_NULL(seed);
        ASSERT_EQUAL(seed->get_allocation_strategy(), seeded_vpn::domain::SeedAllocationStrategy::PER_CONNECTION);
    }

    TEST_CASE(GenerateMultipleSeeds) {
        auto generator = seeded_vpn::infrastructure::SeedGenerator();
        std::vector<std::unique_ptr<seeded_vpn::domain::Seed>> seeds;
        
        for (int i = 0; i < 10; ++i) {
            seeds.push_back(generator.generate_seed());
        }
        
        ASSERT_EQUAL(seeds.size(), 10);
        
        for (const auto& seed : seeds) {
            ASSERT_NOT_NULL(seed);
            ASSERT_TRUE(seed->is_valid());
        }
        
        auto first_id = seeds[0]->get_id();
        auto second_id = seeds[1]->get_id();
        ASSERT_NOT_EQUAL(first_id, second_id);
    }

    TEST_CASE(SeedValidation) {
        auto generator = seeded_vpn::infrastructure::SeedGenerator();
        auto seed = generator.generate_seed();
        
        ASSERT_TRUE(seed->is_valid());
        ASSERT_FALSE(seed->get_id().empty());
        ASSERT_GREATER(seed->get_address_pool().size(), 0);
        ASSERT_FALSE(seed->is_expired());
    }

    TEARDOWN() {
    }
}
END_TEST_SUITE()

TEST_SUITE(IPv6AddressTests) {
    TEST_CASE(CreateValidIPv6Address) {
        seeded_vpn::domain::IPv6Address addr("2001:db8::1");
        
        ASSERT_TRUE(addr.is_valid());
        ASSERT_EQUAL(addr.to_string(), "2001:db8::1");
    }

    TEST_CASE(CreateInvalidIPv6Address) {
        ASSERT_THROWS(seeded_vpn::domain::IPv6Address("invalid"), std::invalid_argument);
    }

    TEST_CASE(IPv6AddressComparison) {
        seeded_vpn::domain::IPv6Address addr1("2001:db8::1");
        seeded_vpn::domain::IPv6Address addr2("2001:db8::1");
        seeded_vpn::domain::IPv6Address addr3("2001:db8::2");
        
        ASSERT_EQUAL(addr1, addr2);
        ASSERT_NOT_EQUAL(addr1, addr3);
    }

    TEST_CASE(IPv6AddressInSubnet) {
        seeded_vpn::domain::IPv6Address addr("2001:db8::100");
        seeded_vpn::domain::IPv6Address subnet("2001:db8::");
        
        ASSERT_TRUE(addr.is_in_subnet(subnet, 64));
        ASSERT_FALSE(addr.is_in_subnet(subnet, 128));
    }
}
END_TEST_SUITE()

TEST_SUITE(ConnectionTests) {
    TEST_CASE(CreateConnection) {
        auto seed = std::make_shared<seeded_vpn::domain::Seed>("test-seed-id");
        seeded_vpn::domain::IPv6Address client_addr("2001:db8::client");
        seeded_vpn::domain::IPv6Address server_addr("2001:db8::server");
        
        seeded_vpn::domain::Connection connection(seed, client_addr, server_addr);
        
        ASSERT_EQUAL(connection.get_seed_id(), "test-seed-id");
        ASSERT_EQUAL(connection.get_client_address(), client_addr);
        ASSERT_EQUAL(connection.get_server_address(), server_addr);
        ASSERT_EQUAL(connection.get_state(), seeded_vpn::domain::ConnectionState::CONNECTING);
    }

    TEST_CASE(ConnectionStateTransitions) {
        auto seed = std::make_shared<seeded_vpn::domain::Seed>("test-seed-id");
        seeded_vpn::domain::IPv6Address client_addr("2001:db8::client");
        seeded_vpn::domain::IPv6Address server_addr("2001:db8::server");
        
        seeded_vpn::domain::Connection connection(seed, client_addr, server_addr);
        
        ASSERT_EQUAL(connection.get_state(), seeded_vpn::domain::ConnectionState::CONNECTING);
        
        connection.authenticate();
        ASSERT_EQUAL(connection.get_state(), seeded_vpn::domain::ConnectionState::AUTHENTICATING);
        
        connection.establish();
        ASSERT_EQUAL(connection.get_state(), seeded_vpn::domain::ConnectionState::CONNECTED);
        
        connection.disconnect();
        ASSERT_EQUAL(connection.get_state(), seeded_vpn::domain::ConnectionState::DISCONNECTING);
    }

    TEST_CASE(ConnectionTimeout) {
        auto seed = std::make_shared<seeded_vpn::domain::Seed>("test-seed-id");
        seeded_vpn::domain::IPv6Address client_addr("2001:db8::client");
        seeded_vpn::domain::IPv6Address server_addr("2001:db8::server");
        
        seeded_vpn::domain::Connection connection(seed, client_addr, server_addr);
        
        ASSERT_FALSE(connection.is_expired());
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        ASSERT_FALSE(connection.is_expired());
    }
}
END_TEST_SUITE()

TEST_SUITE(PerformanceTests) {
    BENCHMARK_TEST(SeedGenerationPerformance) {
        auto generator = seeded_vpn::infrastructure::SeedGenerator();
        
        for (int i = 0; i < 1000; ++i) {
            auto seed = generator.generate_seed();
            static_cast<void>(seed);
        }
    }

    BENCHMARK_TEST(IPv6AddressCreationPerformance) {
        std::vector<std::string> addresses = {
            "2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4",
            "2001:db8::5", "2001:db8::6", "2001:db8::7", "2001:db8::8"
        };
        
        for (int i = 0; i < 1000; ++i) {
            for (const auto& addr_str : addresses) {
                seeded_vpn::domain::IPv6Address addr(addr_str);
                static_cast<void>(addr);
            }
        }
    }
}
END_TEST_SUITE()

}
