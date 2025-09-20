#pragma once

#include <memory>
#include <queue>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <netinet/in.h>
#include "domain/types.h"
#include "infrastructure/security.h"
#include "infrastructure/vpn_protocol.h"

namespace CipherProxy::Infrastructure {

using SecurityManager = seeded_vpn::infrastructure::SecurityManager;
using VPNPacketHeader = seeded_vpn::infrastructure::VPNPacketHeader;
using ChaCha20Poly1305 = seeded_vpn::infrastructure::ChaCha20Poly1305;
using VPNPacketType = seeded_vpn::infrastructure::VPNPacketType;

enum class PacketType {
    HANDSHAKE,
    DATA,
    CONTROL,
    KEEPALIVE,
    DISCONNECT
};

enum class QoSClass {
    HIGH_PRIORITY,
    NORMAL,
    LOW_PRIORITY,
    BACKGROUND
};

struct ProcessedPacket {
    PacketType type;
    QoSClass qos_class;
    std::vector<uint8_t> data;
    std::string client_id;
    sockaddr_in6 client_addr;
    uint64_t timestamp;
    uint32_t sequence_number;
    bool is_encrypted;
    bool is_valid;
};

struct PacketMetrics {
    uint64_t packets_processed;
    uint64_t packets_dropped;
    uint64_t bytes_processed;
    uint64_t decryption_errors;
    uint64_t validation_failures;
    double avg_processing_time_ms;
    std::chrono::steady_clock::time_point last_reset;
};

class PacketValidator {
private:
    size_t max_packet_size_;
    uint32_t rate_limit_per_second_;
    std::unordered_map<std::string, uint32_t> client_packet_counts_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> client_last_reset_;
    std::mutex validation_mutex_;

public:
    explicit PacketValidator(size_t max_size = 65536, uint32_t rate_limit = 1000);
    
    bool validate_packet_size(const std::vector<uint8_t>& packet);
    bool validate_packet_format(const std::vector<uint8_t>& packet);
    bool validate_rate_limit(const std::string& client_id);
    bool validate_packet_integrity(const ProcessedPacket& packet);
    
    void reset_client_counters(const std::string& client_id);
    void cleanup_old_entries();
    
    PacketType determine_packet_type(const std::vector<uint8_t>& packet);
    QoSClass determine_qos_class(PacketType type, const std::vector<uint8_t>& packet);
};

class DecryptionPipeline {
private:
    std::unique_ptr<SecurityManager> security_manager_;
    std::unordered_map<std::string, std::unique_ptr<ChaCha20Poly1305>> client_ciphers_;
    std::mutex decryption_mutex_;

public:
    explicit DecryptionPipeline(std::unique_ptr<SecurityManager> security_manager);
    
    bool decrypt_packet(ProcessedPacket& packet);
    bool setup_client_cipher(const std::string& client_id, const std::vector<uint8_t>& key);
    void remove_client_cipher(const std::string& client_id);
    
    bool verify_packet_authenticity(const ProcessedPacket& packet);
    bool extract_packet_metadata(ProcessedPacket& packet);
};

class RoutingEngine {
private:
    std::unordered_map<std::string, sockaddr_in6> client_routes_;
    std::unordered_map<std::string, std::vector<std::string>> load_balance_groups_;
    mutable std::mutex routing_mutex_;
    
    uint32_t round_robin_counter_;

public:
    RoutingEngine();
    
    bool add_route(const std::string& client_id, const sockaddr_in6& destination);
    bool remove_route(const std::string& client_id);
    
    std::optional<sockaddr_in6> get_route(const std::string& client_id);
    std::optional<sockaddr_in6> get_load_balanced_route(const std::string& group_name);
    
    void add_to_load_balance_group(const std::string& group_name, const std::string& client_id);
    void remove_from_load_balance_group(const std::string& group_name, const std::string& client_id);
    
    size_t get_route_count() const;
    std::vector<std::string> get_active_clients() const;
};

class QoSManager {
private:
    std::queue<ProcessedPacket> high_priority_queue_;
    std::queue<ProcessedPacket> normal_queue_;
    std::queue<ProcessedPacket> low_priority_queue_;
    std::queue<ProcessedPacket> background_queue_;
    
    mutable std::mutex qos_mutex_;
    std::condition_variable qos_condition_;
    
    size_t max_queue_size_;
    std::atomic<bool> processing_enabled_;

public:
    explicit QoSManager(size_t max_queue_size = 10000);
    
    bool enqueue_packet(const ProcessedPacket& packet);
    bool dequeue_packet(ProcessedPacket& packet);
    
    void enable_processing();
    void disable_processing();
    
    size_t get_queue_size(QoSClass qos_class) const;
    size_t get_total_queue_size() const;
    
    void clear_queues();
    void drop_low_priority_packets(size_t count);
};

class EgressProcessor {
private:
    std::function<bool(const std::vector<uint8_t>&, const sockaddr_in6&)> send_callback_;
    std::unique_ptr<SecurityManager> security_manager_;
    std::mutex egress_mutex_;

public:
    explicit EgressProcessor(std::unique_ptr<SecurityManager> security_manager);
    
    void set_send_callback(std::function<bool(const std::vector<uint8_t>&, const sockaddr_in6&)> callback);
    
    bool process_outgoing_packet(const ProcessedPacket& packet);
    bool encrypt_and_send(const ProcessedPacket& packet);
    
    bool send_control_packet(const std::string& client_id, const sockaddr_in6& dest_addr, 
                           const std::vector<uint8_t>& control_data);
    bool send_keepalive(const std::string& client_id, const sockaddr_in6& dest_addr);
    bool send_disconnect(const std::string& client_id, const sockaddr_in6& dest_addr);
};

class PacketProcessingPipeline {
private:
    std::unique_ptr<PacketValidator> validator_;
    std::unique_ptr<DecryptionPipeline> decryption_pipeline_;
    std::unique_ptr<RoutingEngine> routing_engine_;
    std::unique_ptr<QoSManager> qos_manager_;
    std::unique_ptr<EgressProcessor> egress_processor_;
    
    std::vector<std::thread> processing_threads_;
    std::atomic<bool> running_;
    
    PacketMetrics metrics_;
    mutable std::mutex metrics_mutex_;
    
    std::queue<std::pair<std::vector<uint8_t>, sockaddr_in6>> ingress_queue_;
    std::mutex ingress_mutex_;
    std::condition_variable ingress_condition_;

    void processing_thread_loop();
    void process_ingress_packet(const std::vector<uint8_t>& raw_packet, const sockaddr_in6& client_addr);
    void update_metrics(const ProcessedPacket& packet, double processing_time_ms);

public:
    explicit PacketProcessingPipeline(std::unique_ptr<SecurityManager> security_manager);
    ~PacketProcessingPipeline();
    
    bool start(size_t num_threads = 4);
    void stop();
    
    void enqueue_raw_packet(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr);
    
    void set_send_callback(std::function<bool(const std::vector<uint8_t>&, const sockaddr_in6&)> callback);
    
    RoutingEngine* get_routing_engine() { return routing_engine_.get(); }
    QoSManager* get_qos_manager() { return qos_manager_.get(); }
    PacketMetrics get_metrics() const;
    
    void reset_metrics();
    void configure_rate_limits(uint32_t packets_per_second);
    void configure_qos_limits(size_t max_queue_size);
    
    bool add_client_route(const std::string& client_id, const sockaddr_in6& destination);
    bool remove_client_route(const std::string& client_id);
    
    bool send_to_client(const std::string& client_id, const std::vector<uint8_t>& data);
    bool broadcast_to_all_clients(const std::vector<uint8_t>& data);
};

}
