#include "testing/test_framework.h"
#include "infrastructure/async_socket_manager.h"
#include "infrastructure/packet_processing_pipeline.h"
#include "infrastructure/seed_generator.h"
#include "infrastructure/performance_optimizer.h"
#include <chrono>
#include <vector>
#include <thread>
#include <atomic>

namespace seeded_vpn::testing {

TEST_SUITE(PerformanceBenchmarks) {
    BENCHMARK_TEST(SeedGenerationThroughput) {
        auto generator = seeded_vpn::infrastructure::SeedGenerator();
        constexpr int iterations = 10000;
        
        for (int i = 0; i < iterations; ++i) {
            auto seed = generator.generate_seed();
            static_cast<void>(seed);
        }
    }

    BENCHMARK_TEST(PacketProcessingThroughput) {
        auto processor = seeded_vpn::infrastructure::PacketProcessor();
        
        std::vector<uint8_t> test_packet = {
            0x60, 0x00, 0x00, 0x00,
            0x00, 0x08, 0x11, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        };
        
        constexpr int iterations = 50000;
        
        for (int i = 0; i < iterations; ++i) {
            auto result = processor.process_packet(test_packet);
            static_cast<void>(result);
        }
    }

    BENCHMARK_TEST(SocketCreationPerformance) {
        auto socket_manager = seeded_vpn::infrastructure::SocketManager();
        constexpr int iterations = 1000;
        
        std::vector<int> sockets;
        sockets.reserve(iterations);
        
        for (int i = 0; i < iterations; ++i) {
            auto socket_id = socket_manager.create_socket(AF_INET6, SOCK_STREAM);
            sockets.push_back(socket_id);
        }
        
        for (auto socket_id : sockets) {
            socket_manager.close_socket(socket_id);
        }
    }

    BENCHMARK_TEST(EncryptionPerformance) {
        auto processor = seeded_vpn::infrastructure::PacketProcessor();
        
        std::vector<uint8_t> large_data(1024 * 1024, 0x42);
        std::string key = "test-encryption-key-32-bytes-long";
        
        constexpr int iterations = 100;
        
        for (int i = 0; i < iterations; ++i) {
            auto encrypted = processor.encrypt_packet(large_data, key);
            static_cast<void>(encrypted);
        }
    }

    BENCHMARK_TEST(DecryptionPerformance) {
        auto processor = seeded_vpn::infrastructure::PacketProcessor();
        
        std::vector<uint8_t> data(1024 * 1024, 0x42);
        std::string key = "test-encryption-key-32-bytes-long";
        
        auto encrypted = processor.encrypt_packet(data, key);
        constexpr int iterations = 100;
        
        for (int i = 0; i < iterations; ++i) {
            auto decrypted = processor.decrypt_packet(encrypted, key);
            static_cast<void>(decrypted);
        }
    }
}
END_TEST_SUITE()

TEST_SUITE(ConcurrencyBenchmarks) {
    BENCHMARK_TEST(MultiThreadedSeedGeneration) {
        constexpr int num_threads = 8;
        constexpr int seeds_per_thread = 1000;
        
        std::vector<std::thread> threads;
        std::atomic<int> total_seeds{0};
        
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&total_seeds, seeds_per_thread]() {
                auto generator = seeded_vpn::infrastructure::SeedGenerator();
                for (int i = 0; i < seeds_per_thread; ++i) {
                    auto seed = generator.generate_seed();
                    if (seed) {
                        total_seeds.fetch_add(1);
                    }
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        ASSERT_EQUAL(total_seeds.load(), num_threads * seeds_per_thread);
    }

    BENCHMARK_TEST(ConcurrentPacketProcessing) {
        constexpr int num_threads = 4;
        constexpr int packets_per_thread = 5000;
        
        std::vector<uint8_t> test_packet = {
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        };
        
        std::vector<std::thread> threads;
        std::atomic<int> processed_packets{0};
        
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&test_packet, &processed_packets, packets_per_thread]() {
                auto processor = seeded_vpn::infrastructure::PacketProcessor();
                for (int i = 0; i < packets_per_thread; ++i) {
                    auto result = processor.process_packet(test_packet);
                    if (result.is_valid) {
                        processed_packets.fetch_add(1);
                    }
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        ASSERT_EQUAL(processed_packets.load(), num_threads * packets_per_thread);
    }

    BENCHMARK_TEST(MemoryPoolPerformance) {
        auto pool = seeded_vpn::infrastructure::ObjectPool<std::vector<uint8_t>>(1000);
        constexpr int iterations = 10000;
        
        for (int i = 0; i < iterations; ++i) {
            auto obj = pool.acquire();
            obj->resize(1024);
            pool.release(std::move(obj));
        }
    }
}
END_TEST_SUITE()

TEST_SUITE(ScalabilityBenchmarks) {
    BENCHMARK_TEST(ConnectionScaling) {
        auto socket_manager = seeded_vpn::infrastructure::SocketManager();
        constexpr int max_connections = 1000;
        
        std::vector<int> sockets;
        sockets.reserve(max_connections);
        
        for (int i = 0; i < max_connections; ++i) {
            auto socket_id = socket_manager.create_socket(AF_INET6, SOCK_STREAM);
            if (socket_id >= 0) {
                sockets.push_back(socket_id);
            }
        }
        
        ASSERT_GREATER_EQUAL(sockets.size(), max_connections * 0.9);
        
        for (auto socket_id : sockets) {
            socket_manager.close_socket(socket_id);
        }
    }

    BENCHMARK_TEST(SeedPoolScaling) {
        auto generator = seeded_vpn::infrastructure::SeedGenerator();
        constexpr int pool_size = 10000;
        
        std::vector<std::unique_ptr<seeded_vpn::domain::Seed>> seed_pool;
        seed_pool.reserve(pool_size);
        
        for (int i = 0; i < pool_size; ++i) {
            auto seed = generator.generate_seed();
            if (seed) {
                seed_pool.push_back(std::move(seed));
            }
        }
        
        ASSERT_EQUAL(seed_pool.size(), pool_size);
        
        std::set<std::string> unique_ids;
        for (const auto& seed : seed_pool) {
            unique_ids.insert(seed->get_id());
        }
        
        ASSERT_EQUAL(unique_ids.size(), pool_size);
    }

    BENCHMARK_TEST(MemoryUsageScaling) {
        constexpr int large_allocation_count = 1000;
        constexpr size_t allocation_size = 1024 * 1024;
        
        std::vector<std::unique_ptr<uint8_t[]>> allocations;
        allocations.reserve(large_allocation_count);
        
        for (int i = 0; i < large_allocation_count; ++i) {
            allocations.push_back(std::make_unique<uint8_t[]>(allocation_size));
            std::fill_n(allocations.back().get(), allocation_size, 
                       static_cast<uint8_t>(i % 256));
        }
        
        ASSERT_EQUAL(allocations.size(), large_allocation_count);
        
        for (int i = 0; i < large_allocation_count; ++i) {
            ASSERT_EQUAL(allocations[i][0], static_cast<uint8_t>(i % 256));
        }
    }
}
END_TEST_SUITE()

TEST_SUITE(LatencyBenchmarks) {
    BENCHMARK_TEST(PacketLatency) {
        auto processor = seeded_vpn::infrastructure::PacketProcessor();
        
        std::vector<uint8_t> test_packet = {
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
        };
        
        constexpr int iterations = 1000;
        std::vector<std::chrono::nanoseconds> latencies;
        latencies.reserve(iterations);
        
        for (int i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            auto result = processor.process_packet(test_packet);
            auto end = std::chrono::high_resolution_clock::now();
            
            static_cast<void>(result);
            latencies.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start));
        }
        
        auto total_time = std::accumulate(latencies.begin(), latencies.end(), 
                                        std::chrono::nanoseconds{0});
        auto average_latency = total_time / iterations;
        
        ASSERT_LESS(average_latency.count(), 100000);
    }

    BENCHMARK_TEST(SeedGenerationLatency) {
        auto generator = seeded_vpn::infrastructure::SeedGenerator();
        constexpr int iterations = 100;
        
        std::vector<std::chrono::nanoseconds> latencies;
        latencies.reserve(iterations);
        
        for (int i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            auto seed = generator.generate_seed();
            auto end = std::chrono::high_resolution_clock::now();
            
            static_cast<void>(seed);
            latencies.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start));
        }
        
        auto total_time = std::accumulate(latencies.begin(), latencies.end(), 
                                        std::chrono::nanoseconds{0});
        auto average_latency = total_time / iterations;
        
        ASSERT_LESS(average_latency.count(), 1000000);
    }
}
END_TEST_SUITE()

}
