#include "testing/test_framework.h"
#include "application/services.h"
#include "infrastructure/async_socket_manager.h"
#include "infrastructure/seed_generator.h"
#include "infrastructure/config_manager.h"
#include "infrastructure/error_handler.h"
#include <thread>
#include <chrono>

namespace seeded_vpn::testing {

TEST_SUITE(VPNServerIntegrationTests) {
    SETUP() {
        config_manager = std::make_unique<seeded_vpn::infrastructure::ConfigManager>();
        config_manager->initialize();
        config_manager->set_value("server.port", 8443);
        config_manager->set_value("server.threads", 2);
        config_manager->set_value("server.max_connections", 100);
        
        error_handler = &seeded_vpn::infrastructure::ErrorHandlerManager::instance();
        error_handler->initialize();
        
        vpn_service = std::make_unique<seeded_vpn::application::VPNService>(
            config_manager.get(), error_handler);
    }

    TEST_CASE(ServerStartupAndShutdown) {
        ASSERT_NO_THROW(vpn_service->start());
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        ASSERT_TRUE(vpn_service->is_running());
        
        ASSERT_NO_THROW(vpn_service->stop());
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        ASSERT_FALSE(vpn_service->is_running());
    }

    TEST_CASE(ClientConnectionLifecycle) {
        vpn_service->start();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        auto client_socket = socket(AF_INET6, SOCK_STREAM, 0);
        ASSERT_GREATER_EQUAL(client_socket, 0);
        
        sockaddr_in6 server_addr{};
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_addr = in6addr_loopback;
        server_addr.sin6_port = htons(8443);
        
        int result = connect(client_socket, 
            reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));
        
        if (result == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            
            auto connections = vpn_service->get_active_connections();
            ASSERT_GREATER(connections.size(), 0);
        }
        
        close(client_socket);
        vpn_service->stop();
    }

    TEST_CASE(SeedAllocationIntegration) {
        auto seed_generator = seeded_vpn::infrastructure::SeedGenerator();
        
        vpn_service->start();
        
        auto seed1 = seed_generator.generate_seed(
            seeded_vpn::domain::SeedAllocationStrategy::PER_CONNECTION);
        auto seed2 = seed_generator.generate_seed(
            seeded_vpn::domain::SeedAllocationStrategy::PER_CLIENT);
        
        ASSERT_NOT_NULL(seed1);
        ASSERT_NOT_NULL(seed2);
        ASSERT_NOT_EQUAL(seed1->get_id(), seed2->get_id());
        
        vpn_service->stop();
    }

    TEST_CASE(ErrorHandlingIntegration) {
        vpn_service->start();
        
        try {
            auto socket_manager = seeded_vpn::infrastructure::SocketManager();
            socket_manager.bind_socket(-1, nullptr, 0);
        } catch (...) {
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        ASSERT_TRUE(vpn_service->is_running());
        
        vpn_service->stop();
    }

    TEST_CASE(ConfigurationReloadIntegration) {
        vpn_service->start();
        
        auto original_threads = config_manager->get_value<int>("server.threads");
        ASSERT_EQUAL(original_threads, 2);
        
        config_manager->set_value("server.threads", 4);
        config_manager->reload();
        
        auto updated_threads = config_manager->get_value<int>("server.threads");
        ASSERT_EQUAL(updated_threads, 4);
        
        vpn_service->stop();
    }

    TEARDOWN() {
        if (vpn_service && vpn_service->is_running()) {
            vpn_service->stop();
        }
        vpn_service.reset();
        config_manager.reset();
    }

private:
    std::unique_ptr<seeded_vpn::infrastructure::ConfigManager> config_manager;
    std::unique_ptr<seeded_vpn::application::VPNService> vpn_service;
    seeded_vpn::infrastructure::ErrorHandlerManager* error_handler;
}
END_TEST_SUITE()

TEST_SUITE(PacketFlowIntegrationTests) {
    SETUP() {
        packet_processor = std::make_unique<seeded_vpn::infrastructure::PacketProcessor>();
        socket_manager = std::make_unique<seeded_vpn::infrastructure::SocketManager>();
    }

    TEST_CASE(EndToEndPacketProcessing) {
        std::vector<uint8_t> original_packet = {
            0x60, 0x00, 0x00, 0x00,
            0x00, 0x20, 0x11, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        };
        
        original_packet.resize(72, 0x42);
        
        auto processed = packet_processor->process_packet(original_packet);
        ASSERT_TRUE(processed.is_valid);
        
        auto encrypted = packet_processor->encrypt_packet(original_packet, "test-key");
        ASSERT_GREATER(encrypted.size(), 0);
        ASSERT_NOT_EQUAL(encrypted, original_packet);
        
        auto decrypted = packet_processor->decrypt_packet(encrypted, "test-key");
        ASSERT_EQUAL(decrypted, original_packet);
    }

    TEST_CASE(FragmentationAndReassembly) {
        std::vector<uint8_t> large_packet(3000, 0x55);
        
        auto fragments = packet_processor->fragment_packet(large_packet, 1280);
        ASSERT_GREATER(fragments.size(), 1);
        
        auto reassembled = packet_processor->reassemble_packet(fragments);
        ASSERT_EQUAL(reassembled.size(), large_packet.size());
        ASSERT_EQUAL(reassembled, large_packet);
    }

    TEST_CASE(QoSProcessing) {
        std::vector<uint8_t> high_priority_packet = {
            0x68, 0x00, 0x00, 0x00,
            0x00, 0x08, 0x11, 0x40
        };
        
        std::vector<uint8_t> low_priority_packet = {
            0x60, 0x00, 0x00, 0x00,
            0x00, 0x08, 0x11, 0x40
        };
        
        auto high_result = packet_processor->process_packet(high_priority_packet);
        auto low_result = packet_processor->process_packet(low_priority_packet);
        
        ASSERT_TRUE(high_result.is_valid);
        ASSERT_TRUE(low_result.is_valid);
        ASSERT_GREATER(high_result.priority, low_result.priority);
    }

    TEARDOWN() {
        packet_processor.reset();
        socket_manager.reset();
    }

private:
    std::unique_ptr<seeded_vpn::infrastructure::PacketProcessor> packet_processor;
    std::unique_ptr<seeded_vpn::infrastructure::SocketManager> socket_manager;
}
END_TEST_SUITE()

TEST_SUITE(SecurityIntegrationTests) {
    SETUP() {
        security_layer = std::make_unique<seeded_vpn::infrastructure::SecurityLayer>();
        security_layer->initialize();
    }

    TEST_CASE(HandshakeProtocol) {
        auto client_context = security_layer->create_client_context();
        auto server_context = security_layer->create_server_context();
        
        ASSERT_NOT_NULL(client_context);
        ASSERT_NOT_NULL(server_context);
        
        auto client_hello = security_layer->generate_client_hello(client_context);
        ASSERT_GREATER(client_hello.size(), 0);
        
        auto server_response = security_layer->process_client_hello(
            server_context, client_hello);
        ASSERT_GREATER(server_response.size(), 0);
        
        auto handshake_complete = security_layer->complete_handshake(
            client_context, server_response);
        ASSERT_TRUE(handshake_complete);
    }

    TEST_CASE(EncryptionDecryption) {
        std::vector<uint8_t> plaintext = {
            'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'
        };
        
        auto key = security_layer->generate_session_key();
        ASSERT_EQUAL(key.size(), 32);
        
        auto encrypted = security_layer->encrypt(plaintext, key);
        ASSERT_GREATER(encrypted.size(), plaintext.size());
        
        auto decrypted = security_layer->decrypt(encrypted, key);
        ASSERT_EQUAL(decrypted, plaintext);
    }

    TEST_CASE(CertificateValidation) {
        auto test_cert = security_layer->load_certificate("test_cert.pem");
        
        if (test_cert) {
            ASSERT_TRUE(security_layer->validate_certificate(test_cert));
        }
    }

    TEST_CASE(AntiReplayProtection) {
        auto key = security_layer->generate_session_key();
        std::vector<uint8_t> packet = {'t', 'e', 's', 't'};
        
        auto encrypted1 = security_layer->encrypt_with_sequence(packet, key, 1);
        auto encrypted2 = security_layer->encrypt_with_sequence(packet, key, 2);
        
        ASSERT_NOT_EQUAL(encrypted1, encrypted2);
        
        ASSERT_TRUE(security_layer->validate_sequence_number(encrypted1, 1));
        ASSERT_FALSE(security_layer->validate_sequence_number(encrypted1, 1));
    }

    TEARDOWN() {
        security_layer.reset();
    }

private:
    std::unique_ptr<seeded_vpn::infrastructure::SecurityLayer> security_layer;
}
END_TEST_SUITE()

}
