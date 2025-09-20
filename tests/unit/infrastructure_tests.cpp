#include "testing/test_framework.h"
#include "infrastructure/repositories.h"
#include "infrastructure/async_socket_manager.h"
#include "infrastructure/packet_processing_pipeline.h"
#include "infrastructure/config_manager.h"
#include <memory>

namespace seeded_vpn::testing {

TEST_SUITE(SeedRepositoryTests) {
    SETUP() {
        test_repo = std::make_unique<seeded_vpn::infrastructure::SeedRepository>();
    }

    TEST_CASE(StoreSeed) {
        auto seed = std::make_shared<seeded_vpn::domain::Seed>("test-seed-123");
        
        ASSERT_NO_THROW(test_repo->store(seed));
        
        auto retrieved = test_repo->find_by_id("test-seed-123");
        ASSERT_NOT_NULL(retrieved);
        ASSERT_EQUAL(retrieved->get_id(), "test-seed-123");
    }

    TEST_CASE(FindNonExistentSeed) {
        auto result = test_repo->find_by_id("non-existent");
        ASSERT_NULL(result);
    }

    TEST_CASE(ListSeedsByStrategy) {
        auto seed1 = std::make_shared<seeded_vpn::domain::Seed>("seed-1");
        auto seed2 = std::make_shared<seeded_vpn::domain::Seed>("seed-2");
        
        seed1->set_allocation_strategy(seeded_vpn::domain::SeedAllocationStrategy::PER_CONNECTION);
        seed2->set_allocation_strategy(seeded_vpn::domain::SeedAllocationStrategy::PER_CLIENT);
        
        test_repo->store(seed1);
        test_repo->store(seed2);
        
        auto per_connection_seeds = test_repo->find_by_strategy(
            seeded_vpn::domain::SeedAllocationStrategy::PER_CONNECTION);
        
        ASSERT_EQUAL(per_connection_seeds.size(), 1);
        ASSERT_EQUAL(per_connection_seeds[0]->get_id(), "seed-1");
    }

    TEST_CASE(RemoveSeed) {
        auto seed = std::make_shared<seeded_vpn::domain::Seed>("test-seed-remove");
        test_repo->store(seed);
        
        auto retrieved = test_repo->find_by_id("test-seed-remove");
        ASSERT_NOT_NULL(retrieved);
        
        test_repo->remove("test-seed-remove");
        
        auto removed = test_repo->find_by_id("test-seed-remove");
        ASSERT_NULL(removed);
    }

    TEARDOWN() {
        test_repo.reset();
    }

private:
    std::unique_ptr<seeded_vpn::infrastructure::SeedRepository> test_repo;
}
END_TEST_SUITE()

TEST_SUITE(SocketManagerTests) {
    SETUP() {
        socket_manager = std::make_unique<seeded_vpn::infrastructure::SocketManager>();
    }

    TEST_CASE(CreateSocket) {
        auto socket_id = socket_manager->create_socket(AF_INET6, SOCK_STREAM);
        
        ASSERT_GREATER_EQUAL(socket_id, 0);
        ASSERT_TRUE(socket_manager->is_socket_valid(socket_id));
    }

    TEST_CASE(BindSocket) {
        auto socket_id = socket_manager->create_socket(AF_INET6, SOCK_STREAM);
        
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(0);
        
        ASSERT_NO_THROW(socket_manager->bind_socket(socket_id, 
            reinterpret_cast<sockaddr*>(&addr), sizeof(addr)));
    }

    TEST_CASE(CloseSocket) {
        auto socket_id = socket_manager->create_socket(AF_INET6, SOCK_STREAM);
        
        ASSERT_TRUE(socket_manager->is_socket_valid(socket_id));
        
        socket_manager->close_socket(socket_id);
        
        ASSERT_FALSE(socket_manager->is_socket_valid(socket_id));
    }

    TEST_CASE(EpollIntegration) {
        auto socket_id = socket_manager->create_socket(AF_INET6, SOCK_STREAM);
        
        ASSERT_NO_THROW(socket_manager->add_to_epoll(socket_id, EPOLLIN));
        ASSERT_NO_THROW(socket_manager->remove_from_epoll(socket_id));
    }

    TEARDOWN() {
        socket_manager.reset();
    }

private:
    std::unique_ptr<seeded_vpn::infrastructure::SocketManager> socket_manager;
}
END_TEST_SUITE()

TEST_SUITE(PacketProcessorTests) {
    SETUP() {
        packet_processor = std::make_unique<seeded_vpn::infrastructure::PacketProcessor>();
    }

    TEST_CASE(ProcessValidPacket) {
        std::vector<uint8_t> test_packet = {
            0x60, 0x00, 0x00, 0x00,
            0x00, 0x08, 0x11, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        };
        
        auto result = packet_processor->process_packet(test_packet);
        
        ASSERT_TRUE(result.is_valid);
        ASSERT_EQUAL(result.protocol_version, 6);
    }

    TEST_CASE(ProcessInvalidPacket) {
        std::vector<uint8_t> invalid_packet = {0x40, 0x00};
        
        auto result = packet_processor->process_packet(invalid_packet);
        
        ASSERT_FALSE(result.is_valid);
    }

    TEST_CASE(ValidatePacketChecksum) {
        std::vector<uint8_t> test_packet = {
            0x60, 0x00, 0x00, 0x00,
            0x00, 0x08, 0x11, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        };
        
        ASSERT_TRUE(packet_processor->validate_checksum(test_packet));
    }

    TEST_CASE(FragmentPacket) {
        std::vector<uint8_t> large_packet(2000, 0x42);
        
        auto fragments = packet_processor->fragment_packet(large_packet, 1280);
        
        ASSERT_GREATER(fragments.size(), 1);
        
        for (const auto& fragment : fragments) {
            ASSERT_LESS_EQUAL(fragment.size(), 1280);
        }
    }

    TEST_CASE(ReassemblePacket) {
        std::vector<uint8_t> original_packet(2000, 0x42);
        auto fragments = packet_processor->fragment_packet(original_packet, 1280);
        
        auto reassembled = packet_processor->reassemble_packet(fragments);
        
        ASSERT_EQUAL(reassembled.size(), original_packet.size());
        ASSERT_EQUAL(reassembled, original_packet);
    }

    TEARDOWN() {
        packet_processor.reset();
    }

private:
    std::unique_ptr<seeded_vpn::infrastructure::PacketProcessor> packet_processor;
}
END_TEST_SUITE()

TEST_SUITE(ConfigManagerTests) {
    SETUP() {
        config_manager = std::make_unique<seeded_vpn::infrastructure::ConfigManager>();
        config_manager->initialize();
    }

    TEST_CASE(LoadConfiguration) {
        ASSERT_NO_THROW(config_manager->load_from_file("test_config.yaml"));
    }

    TEST_CASE(GetConfigurationValue) {
        config_manager->set_value("test.key", "test_value");
        
        auto value = config_manager->get_value<std::string>("test.key");
        ASSERT_EQUAL(value, "test_value");
    }

    TEST_CASE(ConfigurationValidation) {
        config_manager->set_value("server.port", 8080);
        config_manager->set_value("server.threads", 4);
        
        ASSERT_TRUE(config_manager->validate());
    }

    TEST_CASE(EnvironmentVariableOverride) {
        setenv("VPN_SERVER_PORT", "9090", 1);
        
        config_manager->load_environment_variables();
        
        auto port = config_manager->get_value<int>("server.port");
        ASSERT_EQUAL(port, 9090);
        
        unsetenv("VPN_SERVER_PORT");
    }

    TEST_CASE(ConfigurationReload) {
        config_manager->set_value("test.reload", "original");
        
        auto original = config_manager->get_value<std::string>("test.reload");
        ASSERT_EQUAL(original, "original");
        
        config_manager->set_value("test.reload", "updated");
        config_manager->reload();
        
        auto updated = config_manager->get_value<std::string>("test.reload");
        ASSERT_EQUAL(updated, "updated");
    }

    TEARDOWN() {
        config_manager.reset();
    }

private:
    std::unique_ptr<seeded_vpn::infrastructure::ConfigManager> config_manager;
}
END_TEST_SUITE()

}
