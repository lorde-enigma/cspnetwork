#include "../../include/domain/entities.h"
#include <algorithm>
#include <stdexcept>
#include <chrono>

namespace seeded_vpn::domain {

VPNConnection::VPNConnection(ConnectionId id, const ClientId& client_id, const IPv6Address& assigned_address)
    : context_{id, client_id, assigned_address, ConnectionState::CONNECTING, std::chrono::steady_clock::now(), std::chrono::steady_clock::now()},
      last_activity_timestamp_(std::chrono::steady_clock::now()),
      bytes_transferred_(0),
      packets_transferred_(0),
      connection_quality_(0.0),
      encryption_enabled_(true) {
}

void VPNConnection::update_state(ConnectionState new_state) {
    validate_state_transition(context_.state, new_state);
    context_.state = new_state;
    context_.last_activity = std::chrono::steady_clock::now();
    last_activity_timestamp_ = context_.last_activity;
}

void VPNConnection::record_activity() {
    last_activity_timestamp_ = std::chrono::steady_clock::now();
    context_.last_activity = last_activity_timestamp_;
}

void VPNConnection::update_statistics(uint64_t bytes_sent, uint64_t bytes_received, uint32_t packets_sent, uint32_t packets_received) {
    bytes_transferred_ += bytes_sent + bytes_received;
    packets_transferred_ += packets_sent + packets_received;
    
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity_timestamp_).count();
    
    if (duration > 0) {
        connection_quality_ = static_cast<double>(bytes_transferred_) / duration;
    }
    
    record_activity();
}

bool VPNConnection::is_active() const {
    return context_.state == ConnectionState::ACTIVE;
}

bool VPNConnection::is_expired(std::chrono::seconds timeout) const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - last_activity_timestamp_) > timeout;
}

ConnectionContext VPNConnection::get_context() const {
    return context_;
}

void VPNConnection::set_encryption_key(const std::vector<uint8_t>& key) {
    if (key.size() != 32) {
        throw std::invalid_argument("encryption key must be 32 bytes");
    }
    encryption_key_ = key;
    encryption_enabled_ = true;
}

void VPNConnection::validate_state_transition(ConnectionState from, ConnectionState to) const {
    switch (from) {
        case ConnectionState::CONNECTING:
            if (to != ConnectionState::ACTIVE && to != ConnectionState::FAILED && to != ConnectionState::TERMINATED) {
                throw std::logic_error("invalid state transition from connecting");
            }
            break;
        case ConnectionState::ACTIVE:
            if (to != ConnectionState::TERMINATED && to != ConnectionState::SUSPENDED) {
                throw std::logic_error("invalid state transition from active");
            }
            break;
        case ConnectionState::SUSPENDED:
            if (to != ConnectionState::ACTIVE && to != ConnectionState::TERMINATED) {
                throw std::logic_error("invalid state transition from suspended");
            }
            break;
        case ConnectionState::AUTHENTICATING:
            if (to != ConnectionState::CONNECTING && to != ConnectionState::FAILED) {
                throw std::logic_error("invalid state transition from authenticating");
            }
            break;
        case ConnectionState::CONNECTED:
            if (to != ConnectionState::DISCONNECTING && to != ConnectionState::ERROR) {
                throw std::logic_error("invalid state transition from connected");
            }
            break;
        case ConnectionState::DISCONNECTING:
            if (to != ConnectionState::DISCONNECTED) {
                throw std::logic_error("invalid state transition from disconnecting");
            }
            break;
        case ConnectionState::DISCONNECTED:
            if (to != ConnectionState::CONNECTING) {
                throw std::logic_error("invalid state transition from disconnected");
            }
            break;
        case ConnectionState::ERROR:
            if (to != ConnectionState::CONNECTING && to != ConnectionState::TERMINATED) {
                throw std::logic_error("invalid state transition from error");
            }
            break;
        case ConnectionState::FAILED:
        case ConnectionState::TERMINATED:
            throw std::logic_error("cannot transition from terminal state");
    }
}

SeedManager::SeedManager(std::shared_ptr<ISeedGenerator> generator)
    : seed_generator_(std::move(generator)),
      last_rotation_(std::chrono::steady_clock::now()),
      rotation_interval_(std::chrono::hours(24)),
      seed_history_limit_(100) {
}

SeedValue SeedManager::generate_seed_for_client(const ClientId& client_id, ConnectionId connection_id) {
    std::lock_guard lock(seed_mutex_);
    
    SeedContext context{client_id, connection_id};
    SeedValue new_seed = seed_generator_->generate(context);
    
    if (!seed_generator_->validate_seed(new_seed)) {
        throw std::runtime_error("generated invalid seed for client: " + client_id);
    }
    
    track_seed_usage(new_seed, client_id);
    return new_seed;
}

void SeedManager::rotate_seeds_if_needed() {
    std::lock_guard lock(seed_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    if (now - last_rotation_ >= rotation_interval_) {
        seed_generator_->rotate_base_seed();
        last_rotation_ = now;
        cleanup_seed_history();
    }
}

void SeedManager::set_rotation_interval(std::chrono::seconds interval) {
    std::lock_guard lock(seed_mutex_);
    rotation_interval_ = interval;
}

std::vector<SeedValue> SeedManager::get_active_seeds() const {
    std::shared_lock lock(seed_mutex_);
    std::vector<SeedValue> active_seeds;
    
    for (const auto& [seed, usage] : seed_usage_history_) {
        if (usage.is_active) {
            active_seeds.push_back(seed);
        }
    }
    
    return active_seeds;
}

void SeedManager::invalidate_seed(SeedValue seed) {
    std::lock_guard lock(seed_mutex_);
    auto it = seed_usage_history_.find(seed);
    if (it != seed_usage_history_.end()) {
        it->second.is_active = false;
        it->second.invalidated_at = std::chrono::steady_clock::now();
    }
}

void SeedManager::track_seed_usage(SeedValue seed, const ClientId& client_id) {
    SeedUsage usage{
        client_id,
        std::chrono::steady_clock::now(),
        std::nullopt,
        true
    };
    
    seed_usage_history_[seed] = usage;
}

void SeedManager::cleanup_seed_history() {
    if (seed_usage_history_.size() <= seed_history_limit_) {
        return;
    }
    
    std::vector<std::pair<SeedValue, SeedUsage>> sorted_history(
        seed_usage_history_.begin(), seed_usage_history_.end());
    
    std::sort(sorted_history.begin(), sorted_history.end(),
        [](const auto& a, const auto& b) {
            return a.second.created_at < b.second.created_at;
        });
    
    size_t to_remove = seed_usage_history_.size() - seed_history_limit_;
    for (size_t i = 0; i < to_remove; ++i) {
        seed_usage_history_.erase(sorted_history[i].first);
    }
}

ConnectionManager::ConnectionManager(std::shared_ptr<IConnectionRepository> repository,
                                     std::shared_ptr<ILogger> logger)
    : connection_repository_(std::move(repository)),
      logger_(std::move(logger)),
      max_connections_per_client_(10),
      connection_timeout_(std::chrono::minutes(30)) {
}

std::unique_ptr<VPNConnection> ConnectionManager::create_connection(const ClientId& client_id, 
                                                                    const IPv6Address& assigned_address) {
    validate_client_connection_limit(client_id);
    
    ConnectionId new_id = generate_connection_id();
    auto connection = std::make_unique<VPNConnection>(new_id, client_id, assigned_address);
    
    connection_repository_->store(connection->get_context());
    
    logger_->info("created connection " + std::to_string(new_id) + " for client " + client_id);
    return connection;
}

std::optional<VPNConnection> ConnectionManager::get_connection(ConnectionId id) {
    auto context = connection_repository_->find_by_id(id);
    if (!context) {
        return std::nullopt;
    }
    
    VPNConnection connection(context->connection_id, context->client_id, context->assigned_address);
    connection.update_state(context->state);
    return connection;
}

void ConnectionManager::close_connection(ConnectionId id) {
    auto context = connection_repository_->find_by_id(id);
    if (context) {
        connection_repository_->update_state(id, ConnectionState::TERMINATED);
        logger_->info("closed connection " + std::to_string(id));
    }
}

std::vector<VPNConnection> ConnectionManager::get_client_connections(const ClientId& client_id) {
    auto contexts = connection_repository_->find_by_client(client_id);
    std::vector<VPNConnection> connections;
    
    for (const auto& context : contexts) {
        VPNConnection connection(context.connection_id, context.client_id, context.assigned_address);
        connection.update_state(context.state);
        connections.push_back(std::move(connection));
    }
    
    return connections;
}

void ConnectionManager::cleanup_expired_connections() {
    auto active_contexts = connection_repository_->get_all_active();
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& context : active_contexts) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - context.last_activity) > connection_timeout_) {
            connection_repository_->update_state(context.connection_id, ConnectionState::TERMINATED);
            logger_->warn("expired connection " + std::to_string(context.connection_id) + " due to timeout");
        }
    }
}

void ConnectionManager::set_max_connections_per_client(size_t max_connections) {
    max_connections_per_client_ = max_connections;
}

void ConnectionManager::set_connection_timeout(std::chrono::seconds timeout) {
    connection_timeout_ = timeout;
}

void ConnectionManager::validate_client_connection_limit(const ClientId& client_id) {
    auto client_connections = connection_repository_->find_by_client(client_id);
    
    size_t active_count = std::count_if(client_connections.begin(), client_connections.end(),
        [](const ConnectionContext& context) {
            return context.state == ConnectionState::ACTIVE || context.state == ConnectionState::CONNECTING;
        });
    
    if (active_count >= max_connections_per_client_) {
        throw std::runtime_error("client " + client_id + " has reached maximum connection limit");
    }
}

ConnectionId ConnectionManager::generate_connection_id() {
    static std::atomic<ConnectionId> next_id{1};
    return next_id++;
}

AddressPoolManager::AddressPoolManager(std::shared_ptr<IIPv6AddressManager> address_manager,
                                       std::shared_ptr<ILogger> logger)
    : address_manager_(std::move(address_manager)),
      logger_(std::move(logger)),
      pool_expansion_threshold_(0.8),
      max_pool_size_(100000),
      allocation_timeout_(std::chrono::seconds(10)) {
}

IPv6Address AddressPoolManager::allocate_address(SeedValue seed) {
    std::lock_guard lock(allocation_mutex_);
    
    try {
        IPv6Address allocated_address = address_manager_->allocate(seed);
        track_allocation(allocated_address, seed);
        
        check_pool_expansion_needed();
        
        logger_->debug("allocated address for seed " + std::to_string(seed));
        return allocated_address;
        
    } catch (const std::exception& e) {
        logger_->error("failed to allocate address for seed " + std::to_string(seed) + ": " + e.what());
        throw;
    }
}

void AddressPoolManager::release_address(const IPv6Address& address) {
    std::lock_guard lock(allocation_mutex_);
    
    address_manager_->release(address);
    
    auto it = allocation_tracking_.find(address);
    if (it != allocation_tracking_.end()) {
        allocation_tracking_.erase(it);
    }
    
    logger_->debug("released address");
}

bool AddressPoolManager::is_address_available(const IPv6Address& address) {
    return address_manager_->is_available(address);
}

std::vector<IPv6Address> AddressPoolManager::get_allocated_addresses() {
    return address_manager_->get_active_addresses();
}

size_t AddressPoolManager::get_pool_utilization() const {
    std::shared_lock lock(allocation_mutex_);
    size_t total_size = address_manager_->get_pool_size();
    size_t allocated_count = allocation_tracking_.size();
    
    return total_size > 0 ? (allocated_count * 100) / total_size : 0;
}

void AddressPoolManager::set_expansion_threshold(double threshold) {
    if (threshold < 0.0 || threshold > 1.0) {
        throw std::invalid_argument("expansion threshold must be between 0.0 and 1.0");
    }
    pool_expansion_threshold_ = threshold;
}

void AddressPoolManager::track_allocation(const IPv6Address& address, SeedValue seed) {
    AllocationInfo info{
        seed,
        std::chrono::steady_clock::now()
    };
    allocation_tracking_[address] = info;
}

void AddressPoolManager::check_pool_expansion_needed() {
    double utilization = get_pool_utilization() / 100.0;
    
    if (utilization >= pool_expansion_threshold_) {
        size_t current_size = address_manager_->get_pool_size();
        
        if (current_size < max_pool_size_) {
            if (address_manager_->expand_pool()) {
                logger_->info("expanded address pool due to high utilization: " + 
                            std::to_string(utilization * 100) + "%");
            }
        } else {
            logger_->warn("address pool at maximum size, cannot expand further");
        }
    }
}

SecurityValidator::SecurityValidator(std::shared_ptr<ICryptographyService> crypto_service,
                                     std::shared_ptr<ILogger> logger)
    : crypto_service_(std::move(crypto_service)),
      logger_(std::move(logger)),
      max_failed_attempts_(5),
      lockout_duration_(std::chrono::minutes(15)) {
}

bool SecurityValidator::validate_client_identity(const ClientId& client_id, 
                                                const std::vector<uint8_t>& credentials) {
    std::lock_guard lock(validation_mutex_);
    
    if (is_client_locked_out(client_id)) {
        logger_->warn("client " + client_id + " is locked out");
        return false;
    }
    
    bool is_valid = perform_credential_validation(credentials);
    
    if (!is_valid) {
        record_failed_attempt(client_id);
        logger_->warn("failed authentication attempt for client " + client_id);
    } else {
        clear_failed_attempts(client_id);
        logger_->info("successful authentication for client " + client_id);
    }
    
    return is_valid;
}

bool SecurityValidator::validate_connection_integrity(const std::vector<uint8_t>& data,
                                                     const std::vector<uint8_t>& signature,
                                                     const std::vector<uint8_t>& public_key) {
    try {
        return crypto_service_->verify_signature(data, signature, public_key);
    } catch (const std::exception& e) {
        logger_->error("connection integrity validation failed: " + std::string(e.what()));
        return false;
    }
}

std::vector<uint8_t> SecurityValidator::generate_session_key() {
    try {
        return crypto_service_->generate_key();
    } catch (const std::exception& e) {
        logger_->error("session key generation failed: " + std::string(e.what()));
        throw;
    }
}

bool SecurityValidator::is_client_locked_out(const ClientId& client_id) {
    auto it = failed_attempts_.find(client_id);
    if (it == failed_attempts_.end()) {
        return false;
    }
    
    const auto& attempt_info = it->second;
    if (attempt_info.attempt_count < max_failed_attempts_) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    return now - attempt_info.last_attempt < lockout_duration_;
}

void SecurityValidator::record_failed_attempt(const ClientId& client_id) {
    auto now = std::chrono::steady_clock::now();
    auto it = failed_attempts_.find(client_id);
    
    if (it == failed_attempts_.end()) {
        failed_attempts_[client_id] = FailedAttemptInfo{1, now};
    } else {
        it->second.attempt_count++;
        it->second.last_attempt = now;
    }
}

void SecurityValidator::clear_failed_attempts(const ClientId& client_id) {
    failed_attempts_.erase(client_id);
}

bool SecurityValidator::perform_credential_validation(const std::vector<uint8_t>& credentials) {
    return !credentials.empty() && credentials.size() >= 32;
}

}
