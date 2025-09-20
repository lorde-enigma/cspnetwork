#include "infrastructure/packet_processing_pipeline.h"
#include <chrono>
#include <algorithm>
#include <random>

namespace CipherProxy::Infrastructure {

PacketValidator::PacketValidator(size_t max_size, uint32_t rate_limit) 
    : max_packet_size_(max_size), rate_limit_per_second_(rate_limit) {}

bool PacketValidator::validate_packet_size(const std::vector<uint8_t>& packet) {
    return packet.size() > 0 && packet.size() <= max_packet_size_;
}

bool PacketValidator::validate_packet_format(const std::vector<uint8_t>& packet) {
    if (packet.size() < sizeof(VPNPacketHeader)) {
        return false;
    }
    
    const VPNPacketHeader* header = reinterpret_cast<const VPNPacketHeader*>(packet.data());
    
    if (header->version < 1 || header->version > 1) {
        return false;
    }
    
    if (header->payload_length != packet.size() - sizeof(VPNPacketHeader)) {
        return false;
    }
    
    return header->is_valid();
}

bool PacketValidator::validate_rate_limit(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(validation_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto& last_reset = client_last_reset_[client_id];
    auto& packet_count = client_packet_counts_[client_id];
    
    if (now - last_reset >= std::chrono::seconds(1)) {
        last_reset = now;
        packet_count = 0;
    }
    
    if (packet_count >= rate_limit_per_second_) {
        return false;
    }
    
    packet_count++;
    return true;
}

bool PacketValidator::validate_packet_integrity(const ProcessedPacket& packet) {
    if (packet.data.empty()) return false;
    if (packet.client_id.empty()) return false;
    if (packet.timestamp == 0) return false;
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    uint64_t time_diff = std::abs(static_cast<int64_t>(now - packet.timestamp));
    if (time_diff > 30000) {
        return false;
    }
    
    return true;
}

PacketType PacketValidator::determine_packet_type(const std::vector<uint8_t>& packet) {
    if (packet.size() < sizeof(VPNPacketHeader)) {
        return PacketType::DATA;
    }
    
    const VPNPacketHeader* header = reinterpret_cast<const VPNPacketHeader*>(packet.data());
    
    switch (static_cast<VPNPacketType>(header->type)) {
        case VPNPacketType::HANDSHAKE_INIT: return PacketType::HANDSHAKE;
        case VPNPacketType::DATA_PACKET: return PacketType::DATA;
        case VPNPacketType::HANDSHAKE_RESPONSE: return PacketType::CONTROL;
        case VPNPacketType::KEEPALIVE: return PacketType::KEEPALIVE;
        case VPNPacketType::DISCONNECT: return PacketType::DISCONNECT;
        default: return PacketType::DATA;
    }
}

QoSClass PacketValidator::determine_qos_class(PacketType type, const std::vector<uint8_t>& packet) {
    switch (type) {
        case PacketType::HANDSHAKE:
        case PacketType::CONTROL:
            return QoSClass::HIGH_PRIORITY;
        case PacketType::KEEPALIVE:
            return QoSClass::NORMAL;
        case PacketType::DISCONNECT:
            return QoSClass::HIGH_PRIORITY;
        case PacketType::DATA:
        default:
            if (packet.size() > 32768) {
                return QoSClass::LOW_PRIORITY;
            }
            return QoSClass::NORMAL;
    }
}

void PacketValidator::reset_client_counters(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(validation_mutex_);
    client_packet_counts_.erase(client_id);
    client_last_reset_.erase(client_id);
}

void PacketValidator::cleanup_old_entries() {
    std::lock_guard<std::mutex> lock(validation_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto it = client_last_reset_.begin();
    
    while (it != client_last_reset_.end()) {
        if (now - it->second > std::chrono::minutes(5)) {
            client_packet_counts_.erase(it->first);
            it = client_last_reset_.erase(it);
        } else {
            ++it;
        }
    }
}

DecryptionPipeline::DecryptionPipeline(std::unique_ptr<SecurityManager> security_manager)
    : security_manager_(std::move(security_manager)) {}

bool DecryptionPipeline::decrypt_packet(ProcessedPacket& packet) {
    if (!packet.is_encrypted) {
        return true;
    }
    
    std::lock_guard<std::mutex> lock(decryption_mutex_);
    
    auto it = client_ciphers_.find(packet.client_id);
    if (it == client_ciphers_.end()) {
        return false;
    }
    
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> nonce(12);
    std::vector<uint8_t> ciphertext;
    
    if (packet.data.size() < 12) return false;
    
    std::array<uint8_t, 12> nonce_array;
    std::copy(packet.data.begin(), packet.data.begin() + 12, nonce_array.begin());
    ciphertext.assign(packet.data.begin() + 12, packet.data.end());
    
    auto result = it->second->decrypt(ciphertext, nonce_array, {});
    if (!result.empty()) {
        packet.data = result;
        packet.is_encrypted = false;
        return true;
    }
    
    return false;
}

bool DecryptionPipeline::setup_client_cipher(const std::string& client_id, const std::vector<uint8_t>& key) {
    if (key.size() != 32) return false;
    
    std::array<uint8_t, 32> key_array;
    std::copy(key.begin(), key.end(), key_array.begin());
    
    std::lock_guard<std::mutex> lock(decryption_mutex_);
    client_ciphers_[client_id] = std::make_unique<ChaCha20Poly1305>(key_array);
    return true;
}

void DecryptionPipeline::remove_client_cipher(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(decryption_mutex_);
    client_ciphers_.erase(client_id);
}

bool DecryptionPipeline::verify_packet_authenticity(const ProcessedPacket& packet) {
    return security_manager_->verify_packet_integrity(packet.data, packet.client_id);
}

bool DecryptionPipeline::extract_packet_metadata(ProcessedPacket& packet) {
    if (packet.data.size() < sizeof(VPNPacketHeader)) {
        return false;
    }
    
    const VPNPacketHeader* header = reinterpret_cast<const VPNPacketHeader*>(packet.data.data());
    packet.sequence_number = ntohl(header->sequence_number);
    packet.timestamp = be64toh(header->timestamp);
    
    return true;
}

RoutingEngine::RoutingEngine() : round_robin_counter_(0) {}

bool RoutingEngine::add_route(const std::string& client_id, const sockaddr_in6& destination) {
    std::lock_guard<std::mutex> lock(routing_mutex_);
    client_routes_[client_id] = destination;
    return true;
}

bool RoutingEngine::remove_route(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(routing_mutex_);
    return client_routes_.erase(client_id) > 0;
}

std::optional<sockaddr_in6> RoutingEngine::get_route(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(routing_mutex_);
    
    auto it = client_routes_.find(client_id);
    if (it != client_routes_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

std::optional<sockaddr_in6> RoutingEngine::get_load_balanced_route(const std::string& group_name) {
    std::lock_guard<std::mutex> lock(routing_mutex_);
    
    auto group_it = load_balance_groups_.find(group_name);
    if (group_it == load_balance_groups_.end() || group_it->second.empty()) {
        return std::nullopt;
    }
    
    const auto& group = group_it->second;
    size_t index = round_robin_counter_++ % group.size();
    
    auto route_it = client_routes_.find(group[index]);
    if (route_it != client_routes_.end()) {
        return route_it->second;
    }
    
    return std::nullopt;
}

void RoutingEngine::add_to_load_balance_group(const std::string& group_name, const std::string& client_id) {
    std::lock_guard<std::mutex> lock(routing_mutex_);
    load_balance_groups_[group_name].push_back(client_id);
}

void RoutingEngine::remove_from_load_balance_group(const std::string& group_name, const std::string& client_id) {
    std::lock_guard<std::mutex> lock(routing_mutex_);
    
    auto group_it = load_balance_groups_.find(group_name);
    if (group_it != load_balance_groups_.end()) {
        auto& group = group_it->second;
        group.erase(std::remove(group.begin(), group.end(), client_id), group.end());
    }
}

size_t RoutingEngine::get_route_count() const {
    std::lock_guard<std::mutex> lock(routing_mutex_);
    return client_routes_.size();
}

std::vector<std::string> RoutingEngine::get_active_clients() const {
    std::lock_guard<std::mutex> lock(routing_mutex_);
    
    std::vector<std::string> clients;
    for (const auto& pair : client_routes_) {
        clients.push_back(pair.first);
    }
    
    return clients;
}

QoSManager::QoSManager(size_t max_queue_size) 
    : max_queue_size_(max_queue_size), processing_enabled_(true) {}

bool QoSManager::enqueue_packet(const ProcessedPacket& packet) {
    std::lock_guard<std::mutex> lock(qos_mutex_);
    
    if (!processing_enabled_.load()) {
        return false;
    }
    
    switch (packet.qos_class) {
        case QoSClass::HIGH_PRIORITY:
            if (high_priority_queue_.size() >= max_queue_size_) return false;
            high_priority_queue_.push(packet);
            break;
        case QoSClass::NORMAL:
            if (normal_queue_.size() >= max_queue_size_) return false;
            normal_queue_.push(packet);
            break;
        case QoSClass::LOW_PRIORITY:
            if (low_priority_queue_.size() >= max_queue_size_) return false;
            low_priority_queue_.push(packet);
            break;
        case QoSClass::BACKGROUND:
            if (background_queue_.size() >= max_queue_size_) return false;
            background_queue_.push(packet);
            break;
    }
    
    qos_condition_.notify_one();
    return true;
}

bool QoSManager::dequeue_packet(ProcessedPacket& packet) {
    std::unique_lock<std::mutex> lock(qos_mutex_);
    
    qos_condition_.wait(lock, [this] {
        return !processing_enabled_.load() || 
               !high_priority_queue_.empty() || 
               !normal_queue_.empty() || 
               !low_priority_queue_.empty() || 
               !background_queue_.empty();
    });
    
    if (!processing_enabled_.load()) {
        return false;
    }
    
    if (!high_priority_queue_.empty()) {
        packet = high_priority_queue_.front();
        high_priority_queue_.pop();
        return true;
    }
    
    if (!normal_queue_.empty()) {
        packet = normal_queue_.front();
        normal_queue_.pop();
        return true;
    }
    
    if (!low_priority_queue_.empty()) {
        packet = low_priority_queue_.front();
        low_priority_queue_.pop();
        return true;
    }
    
    if (!background_queue_.empty()) {
        packet = background_queue_.front();
        background_queue_.pop();
        return true;
    }
    
    return false;
}

void QoSManager::enable_processing() {
    processing_enabled_.store(true);
    qos_condition_.notify_all();
}

void QoSManager::disable_processing() {
    processing_enabled_.store(false);
    qos_condition_.notify_all();
}

size_t QoSManager::get_queue_size(QoSClass qos_class) const {
    std::lock_guard<std::mutex> lock(qos_mutex_);
    
    switch (qos_class) {
        case QoSClass::HIGH_PRIORITY: return high_priority_queue_.size();
        case QoSClass::NORMAL: return normal_queue_.size();
        case QoSClass::LOW_PRIORITY: return low_priority_queue_.size();
        case QoSClass::BACKGROUND: return background_queue_.size();
    }
    
    return 0;
}

size_t QoSManager::get_total_queue_size() const {
    std::lock_guard<std::mutex> lock(qos_mutex_);
    return high_priority_queue_.size() + normal_queue_.size() + 
           low_priority_queue_.size() + background_queue_.size();
}

void QoSManager::clear_queues() {
    std::lock_guard<std::mutex> lock(qos_mutex_);
    while (!high_priority_queue_.empty()) high_priority_queue_.pop();
    while (!normal_queue_.empty()) normal_queue_.pop();
    while (!low_priority_queue_.empty()) low_priority_queue_.pop();
    while (!background_queue_.empty()) background_queue_.pop();
}

EgressProcessor::EgressProcessor(std::unique_ptr<SecurityManager> security_manager)
    : security_manager_(std::move(security_manager)) {}

void EgressProcessor::set_send_callback(std::function<bool(const std::vector<uint8_t>&, const sockaddr_in6&)> callback) {
    std::lock_guard<std::mutex> lock(egress_mutex_);
    send_callback_ = std::move(callback);
}

bool EgressProcessor::process_outgoing_packet(const ProcessedPacket& packet) {
    if (!send_callback_) {
        return false;
    }
    
    if (packet.is_encrypted) {
        return encrypt_and_send(packet);
    } else {
        return send_callback_(packet.data, packet.client_addr);
    }
}

bool EgressProcessor::encrypt_and_send(const ProcessedPacket& packet) {
    std::vector<uint8_t> encrypted_data;
    
    if (!security_manager_->encrypt_packet(packet.data, packet.client_id, encrypted_data)) {
        return false;
    }
    
    return send_callback_(encrypted_data, packet.client_addr);
}

bool EgressProcessor::send_control_packet(const std::string& client_id, const sockaddr_in6& dest_addr, 
                                        const std::vector<uint8_t>& control_data) {
    if (!send_callback_) return false;
    
    std::vector<uint8_t> encrypted_data;
    if (!security_manager_->encrypt_packet(control_data, client_id, encrypted_data)) {
        return false;
    }
    
    return send_callback_(encrypted_data, dest_addr);
}

bool EgressProcessor::send_keepalive(const std::string& client_id, const sockaddr_in6& dest_addr) {
    std::vector<uint8_t> keepalive_data = {0x04};
    return send_control_packet(client_id, dest_addr, keepalive_data);
}

bool EgressProcessor::send_disconnect(const std::string& client_id, const sockaddr_in6& dest_addr) {
    std::vector<uint8_t> disconnect_data = {0x05};
    return send_control_packet(client_id, dest_addr, disconnect_data);
}

PacketProcessingPipeline::PacketProcessingPipeline(std::unique_ptr<SecurityManager> security_manager) 
    : running_(false) {
    validator_ = std::make_unique<PacketValidator>();
    decryption_pipeline_ = std::make_unique<DecryptionPipeline>(std::move(security_manager));
    routing_engine_ = std::make_unique<RoutingEngine>();
    qos_manager_ = std::make_unique<QoSManager>();
    egress_processor_ = std::make_unique<EgressProcessor>(std::move(security_manager));
    
    metrics_.last_reset = std::chrono::steady_clock::now();
}

PacketProcessingPipeline::~PacketProcessingPipeline() {
    stop();
}

bool PacketProcessingPipeline::start(size_t num_threads) {
    if (running_.load()) return false;
    
    running_.store(true);
    qos_manager_->enable_processing();
    
    processing_threads_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        processing_threads_.emplace_back(&PacketProcessingPipeline::processing_thread_loop, this);
    }
    
    return true;
}

void PacketProcessingPipeline::stop() {
    if (!running_.load()) return;
    
    running_.store(false);
    qos_manager_->disable_processing();
    ingress_condition_.notify_all();
    
    for (auto& thread : processing_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    processing_threads_.clear();
}

void PacketProcessingPipeline::enqueue_raw_packet(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr) {
    std::lock_guard<std::mutex> lock(ingress_mutex_);
    ingress_queue_.emplace(packet, client_addr);
    ingress_condition_.notify_one();
}

void PacketProcessingPipeline::processing_thread_loop() {
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(ingress_mutex_);
        
        ingress_condition_.wait(lock, [this] {
            return !running_.load() || !ingress_queue_.empty();
        });
        
        if (!running_.load()) break;
        
        if (!ingress_queue_.empty()) {
            auto [packet, client_addr] = ingress_queue_.front();
            ingress_queue_.pop();
            lock.unlock();
            
            process_ingress_packet(packet, client_addr);
        }
    }
}

void PacketProcessingPipeline::process_ingress_packet(const std::vector<uint8_t>& raw_packet, const sockaddr_in6& client_addr) {
    auto start_time = std::chrono::steady_clock::now();
    
    if (!validator_->validate_packet_size(raw_packet) || 
        !validator_->validate_packet_format(raw_packet)) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        metrics_.packets_dropped++;
        return;
    }
    
    ProcessedPacket packet{};
    packet.data = raw_packet;
    packet.client_addr = client_addr;
    packet.client_id = "client_" + std::to_string(ntohs(client_addr.sin6_port));
    packet.type = validator_->determine_packet_type(raw_packet);
    packet.qos_class = validator_->determine_qos_class(packet.type, raw_packet);
    packet.is_encrypted = (packet.type != PacketType::HANDSHAKE);
    packet.is_valid = true;
    
    if (!validator_->validate_rate_limit(packet.client_id)) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        metrics_.packets_dropped++;
        return;
    }
    
    if (packet.is_encrypted && !decryption_pipeline_->decrypt_packet(packet)) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        metrics_.decryption_errors++;
        return;
    }
    
    if (!decryption_pipeline_->extract_packet_metadata(packet) ||
        !validator_->validate_packet_integrity(packet)) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        metrics_.validation_failures++;
        return;
    }
    
    if (!qos_manager_->enqueue_packet(packet)) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        metrics_.packets_dropped++;
        return;
    }
    
    auto end_time = std::chrono::steady_clock::now();
    double processing_time = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    update_metrics(packet, processing_time);
}

void PacketProcessingPipeline::update_metrics(const ProcessedPacket& packet, double processing_time_ms) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    metrics_.packets_processed++;
    metrics_.bytes_processed += packet.data.size();
    
    double alpha = 0.1;
    metrics_.avg_processing_time_ms = 
        (1.0 - alpha) * metrics_.avg_processing_time_ms + alpha * processing_time_ms;
}

void PacketProcessingPipeline::set_send_callback(std::function<bool(const std::vector<uint8_t>&, const sockaddr_in6&)> callback) {
    egress_processor_->set_send_callback(std::move(callback));
}

PacketMetrics PacketProcessingPipeline::get_metrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return metrics_;
}

void PacketProcessingPipeline::reset_metrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_ = PacketMetrics{};
    metrics_.last_reset = std::chrono::steady_clock::now();
}

bool PacketProcessingPipeline::add_client_route(const std::string& client_id, const sockaddr_in6& destination) {
    return routing_engine_->add_route(client_id, destination);
}

bool PacketProcessingPipeline::remove_client_route(const std::string& client_id) {
    return routing_engine_->remove_route(client_id);
}

bool PacketProcessingPipeline::send_to_client(const std::string& client_id, const std::vector<uint8_t>& data) {
    auto route = routing_engine_->get_route(client_id);
    if (!route) return false;
    
    ProcessedPacket packet{};
    packet.type = PacketType::DATA;
    packet.qos_class = QoSClass::NORMAL;
    packet.data = data;
    packet.client_id = client_id;
    packet.client_addr = *route;
    packet.is_encrypted = true;
    
    return egress_processor_->process_outgoing_packet(packet);
}

bool PacketProcessingPipeline::broadcast_to_all_clients(const std::vector<uint8_t>& data) {
    auto clients = routing_engine_->get_active_clients();
    bool success = true;
    
    for (const auto& client_id : clients) {
        if (!send_to_client(client_id, data)) {
            success = false;
        }
    }
    
    return success;
}

}
