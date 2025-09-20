#include "infrastructure/seeded_router.h"
#include <algorithm>
#include <random>
#include <numeric>
#include <sstream>
#include <iomanip>

namespace seeded_vpn::infrastructure {

SeededRoute::SeededRoute(const std::string& route_id, const std::vector<std::string>& addresses)
    : route_id_(route_id), seeded_addresses_(addresses), current_address_index_(0) {
    health_.status = RouteStatus::ACTIVE;
    health_.success_rate = 1.0;
    health_.total_packets = 0;
    health_.failed_packets = 0;
    health_.consecutive_failures = 0;
    
    metrics_.bytes_sent = 0;
    metrics_.bytes_received = 0;
    metrics_.packets_sent = 0;
    metrics_.packets_received = 0;
    metrics_.avg_latency_ms = 0.0;
    metrics_.last_activity = std::chrono::steady_clock::now();
}

std::string SeededRoute::get_current_address() {
    std::lock_guard<std::mutex> lock(route_mutex_);
    if (seeded_addresses_.empty()) return "";
    return seeded_addresses_[current_address_index_];
}

std::string SeededRoute::get_next_address() {
    std::lock_guard<std::mutex> lock(route_mutex_);
    if (seeded_addresses_.empty()) return "";
    
    current_address_index_ = (current_address_index_ + 1) % seeded_addresses_.size();
    return seeded_addresses_[current_address_index_];
}

bool SeededRoute::try_fallback_address() {
    std::lock_guard<std::mutex> lock(route_mutex_);
    if (seeded_addresses_.size() <= 1) return false;
    
    size_t original_index = current_address_index_;
    do {
        current_address_index_ = (current_address_index_ + 1) % seeded_addresses_.size();
    } while (current_address_index_ != original_index);
    
    return true;
}

void SeededRoute::report_success(size_t bytes_transferred, double latency_ms) {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    health_.total_packets++;
    health_.last_success = std::chrono::steady_clock::now();
    health_.consecutive_failures = 0;
    health_.success_rate = static_cast<double>(health_.total_packets - health_.failed_packets) / health_.total_packets;
    
    if (health_.success_rate > 0.9) {
        health_.status = RouteStatus::ACTIVE;
    } else if (health_.success_rate > 0.5) {
        health_.status = RouteStatus::DEGRADED;
    }
    
    metrics_.bytes_sent += bytes_transferred;
    metrics_.packets_sent++;
    metrics_.last_activity = std::chrono::steady_clock::now();
    
    double alpha = 0.1;
    metrics_.avg_latency_ms = (1.0 - alpha) * metrics_.avg_latency_ms + alpha * latency_ms;
}

void SeededRoute::report_failure() {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    health_.total_packets++;
    health_.failed_packets++;
    health_.last_failure = std::chrono::steady_clock::now();
    health_.consecutive_failures++;
    health_.success_rate = static_cast<double>(health_.total_packets - health_.failed_packets) / health_.total_packets;
    
    if (health_.consecutive_failures >= 5 || health_.success_rate < 0.1) {
        health_.status = RouteStatus::FAILED;
    } else if (health_.success_rate < 0.5) {
        health_.status = RouteStatus::DEGRADED;
    }
}

RouteHealth SeededRoute::get_health() const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    return health_;
}

TrafficMetrics SeededRoute::get_metrics() const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    return metrics_;
}

bool SeededRoute::is_healthy() const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    return health_.status == RouteStatus::ACTIVE || health_.status == RouteStatus::DEGRADED;
}

void SeededRoute::reset_health() {
    std::lock_guard<std::mutex> lock(route_mutex_);
    health_.status = RouteStatus::ACTIVE;
    health_.success_rate = 1.0;
    health_.total_packets = 0;
    health_.failed_packets = 0;
    health_.consecutive_failures = 0;
}

void SeededRoute::add_seeded_address(const std::string& address) {
    std::lock_guard<std::mutex> lock(route_mutex_);
    seeded_addresses_.push_back(address);
}

void SeededRoute::remove_seeded_address(const std::string& address) {
    std::lock_guard<std::mutex> lock(route_mutex_);
    auto it = std::find(seeded_addresses_.begin(), seeded_addresses_.end(), address);
    if (it != seeded_addresses_.end()) {
        seeded_addresses_.erase(it);
        if (current_address_index_ >= seeded_addresses_.size()) {
            current_address_index_ = 0;
        }
    }
}

size_t SeededRoute::get_address_count() const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    return seeded_addresses_.size();
}

std::vector<std::string> SeededRoute::get_all_addresses() const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    return seeded_addresses_;
}

LoadBalancer::LoadBalancer() : round_robin_index_(0), total_weight_(0.0), use_weighted_balancing_(false) {}

void LoadBalancer::add_target(const std::string& address, uint32_t weight) {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    auto it = std::find_if(targets_.begin(), targets_.end(),
        [&address](const LoadBalanceTarget& target) { return target.address == address; });
    
    if (it == targets_.end()) {
        LoadBalanceTarget target{};
        target.address = address;
        target.weight = weight;
        target.health.status = RouteStatus::ACTIVE;
        target.health.success_rate = 1.0;
        target.is_available = true;
        
        targets_.push_back(target);
        total_weight_ += weight;
    }
}

void LoadBalancer::remove_target(const std::string& address) {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    auto it = std::find_if(targets_.begin(), targets_.end(),
        [&address](const LoadBalanceTarget& target) { return target.address == address; });
    
    if (it != targets_.end()) {
        total_weight_ -= it->weight;
        targets_.erase(it);
    }
}

std::optional<std::string> LoadBalancer::get_next_target() {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    if (targets_.empty()) return std::nullopt;
    
    size_t selected_index;
    if (use_weighted_balancing_) {
        selected_index = select_weighted_target();
    } else {
        selected_index = round_robin_index_.fetch_add(1) % targets_.size();
    }
    
    if (selected_index < targets_.size() && targets_[selected_index].is_available) {
        return targets_[selected_index].address;
    }
    
    return get_best_available_target();
}

std::optional<std::string> LoadBalancer::get_best_available_target() {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    auto best_target = std::max_element(targets_.begin(), targets_.end(),
        [](const LoadBalanceTarget& a, const LoadBalanceTarget& b) {
            if (!a.is_available) return true;
            if (!b.is_available) return false;
            return a.health.success_rate < b.health.success_rate;
        });
    
    if (best_target != targets_.end() && best_target->is_available) {
        return best_target->address;
    }
    
    return std::nullopt;
}

size_t LoadBalancer::select_weighted_target() {
    if (total_weight_ <= 0) return 0;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, total_weight_);
    
    double random_weight = dis(gen);
    double current_weight = 0.0;
    
    for (size_t i = 0; i < targets_.size(); ++i) {
        if (targets_[i].is_available) {
            current_weight += targets_[i].weight;
            if (random_weight <= current_weight) {
                return i;
            }
        }
    }
    
    return 0;
}

void LoadBalancer::report_target_success(const std::string& address, size_t bytes, double latency) {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    auto it = std::find_if(targets_.begin(), targets_.end(),
        [&address](const LoadBalanceTarget& target) { return target.address == address; });
    
    if (it != targets_.end()) {
        it->health.total_packets++;
        it->health.last_success = std::chrono::steady_clock::now();
        it->health.consecutive_failures = 0;
        it->health.success_rate = static_cast<double>(it->health.total_packets - it->health.failed_packets) / it->health.total_packets;
        
        it->metrics.bytes_sent += bytes;
        it->metrics.packets_sent++;
        double alpha = 0.1;
        it->metrics.avg_latency_ms = (1.0 - alpha) * it->metrics.avg_latency_ms + alpha * latency;
        
        if (it->health.success_rate > 0.8) {
            it->health.status = RouteStatus::ACTIVE;
            it->is_available = true;
        }
    }
}

void LoadBalancer::report_target_failure(const std::string& address) {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    auto it = std::find_if(targets_.begin(), targets_.end(),
        [&address](const LoadBalanceTarget& target) { return target.address == address; });
    
    if (it != targets_.end()) {
        it->health.total_packets++;
        it->health.failed_packets++;
        it->health.last_failure = std::chrono::steady_clock::now();
        it->health.consecutive_failures++;
        it->health.success_rate = static_cast<double>(it->health.total_packets - it->health.failed_packets) / it->health.total_packets;
        
        if (it->health.consecutive_failures >= 3 || it->health.success_rate < 0.2) {
            it->health.status = RouteStatus::FAILED;
            it->is_available = false;
        } else if (it->health.success_rate < 0.5) {
            it->health.status = RouteStatus::DEGRADED;
        }
    }
}

void LoadBalancer::enable_weighted_balancing(bool enable) {
    use_weighted_balancing_ = enable;
}

std::vector<LoadBalanceTarget> LoadBalancer::get_target_status() const {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    return targets_;
}

size_t LoadBalancer::get_available_target_count() const {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    return std::count_if(targets_.begin(), targets_.end(),
        [](const LoadBalanceTarget& target) { return target.is_available; });
}

void LoadBalancer::cleanup_failed_targets() {
    std::lock_guard<std::mutex> lock(targets_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto it = targets_.begin();
    
    while (it != targets_.end()) {
        if (it->health.status == RouteStatus::FAILED && 
            (now - it->health.last_failure) > std::chrono::minutes(10)) {
            total_weight_ -= it->weight;
            it = targets_.erase(it);
        } else {
            ++it;
        }
    }
}

NAT66Table::NAT66Table(uint16_t port_start, uint16_t port_end, std::chrono::seconds timeout)
    : next_port_(port_start), port_range_start_(port_start), port_range_end_(port_end), session_timeout_(timeout) {}

std::string NAT66Table::generate_session_key(const std::string& internal_addr, uint16_t internal_port) {
    return internal_addr + ":" + std::to_string(internal_port);
}

uint16_t NAT66Table::allocate_external_port() {
    uint16_t port = next_port_;
    next_port_++;
    if (next_port_ > port_range_end_) {
        next_port_ = port_range_start_;
    }
    return port;
}

bool NAT66Table::create_mapping(const std::string& internal_addr, uint16_t internal_port,
                               const std::string& external_addr, uint16_t& external_port) {
    std::lock_guard<std::mutex> lock(nat_mutex_);
    
    std::string session_key = generate_session_key(internal_addr, internal_port);
    
    auto it = active_sessions_.find(session_key);
    if (it != active_sessions_.end()) {
        external_port = it->second.external_port;
        it->second.last_activity = std::chrono::steady_clock::now();
        return true;
    }
    
    external_port = allocate_external_port();
    
    NAT66Entry entry{};
    entry.internal_addr = internal_addr;
    entry.external_addr = external_addr;
    entry.internal_port = internal_port;
    entry.external_port = external_port;
    entry.last_activity = std::chrono::steady_clock::now();
    entry.bytes_transferred = 0;
    entry.is_persistent = false;
    
    active_sessions_[session_key] = entry;
    port_allocations_[external_addr + ":" + std::to_string(external_port)] = external_port;
    
    return true;
}

bool NAT66Table::translate_outbound(const std::string& internal_addr, uint16_t internal_port,
                                   std::string& external_addr, uint16_t& external_port) {
    std::lock_guard<std::mutex> lock(nat_mutex_);
    
    std::string session_key = generate_session_key(internal_addr, internal_port);
    auto it = active_sessions_.find(session_key);
    
    if (it != active_sessions_.end()) {
        external_addr = it->second.external_addr;
        external_port = it->second.external_port;
        it->second.last_activity = std::chrono::steady_clock::now();
        return true;
    }
    
    return false;
}

bool NAT66Table::translate_inbound(const std::string& external_addr, uint16_t external_port,
                                  std::string& internal_addr, uint16_t& internal_port) {
    std::lock_guard<std::mutex> lock(nat_mutex_);
    
    for (auto& [key, entry] : active_sessions_) {
        if (entry.external_addr == external_addr && entry.external_port == external_port) {
            internal_addr = entry.internal_addr;
            internal_port = entry.internal_port;
            entry.last_activity = std::chrono::steady_clock::now();
            return true;
        }
    }
    
    return false;
}

void NAT66Table::update_session_activity(const std::string& internal_addr, uint16_t internal_port, size_t bytes) {
    std::lock_guard<std::mutex> lock(nat_mutex_);
    
    std::string session_key = generate_session_key(internal_addr, internal_port);
    auto it = active_sessions_.find(session_key);
    
    if (it != active_sessions_.end()) {
        it->second.last_activity = std::chrono::steady_clock::now();
        it->second.bytes_transferred += bytes;
    }
}

void NAT66Table::cleanup_expired_sessions() {
    std::lock_guard<std::mutex> lock(nat_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto it = active_sessions_.begin();
    
    while (it != active_sessions_.end()) {
        if (!it->second.is_persistent && (now - it->second.last_activity) > session_timeout_) {
            std::string port_key = it->second.external_addr + ":" + std::to_string(it->second.external_port);
            port_allocations_.erase(port_key);
            it = active_sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t NAT66Table::get_active_session_count() const {
    std::lock_guard<std::mutex> lock(nat_mutex_);
    return active_sessions_.size();
}

TrafficMonitor::TrafficMonitor() 
    : total_bytes_processed_(0), total_packets_processed_(0) {
    monitor_start_time_ = std::chrono::steady_clock::now();
}

void TrafficMonitor::record_traffic(const std::string& client_id, size_t bytes_in, size_t bytes_out,
                                   size_t packets_in, size_t packets_out) {
    std::lock_guard<std::mutex> lock(monitor_mutex_);
    
    auto& metrics = client_metrics_[client_id];
    auto now = std::chrono::steady_clock::now();
    
    if (metrics.first_seen.time_since_epoch().count() == 0) {
        metrics.first_seen = now;
    }
    
    metrics.bytes_in += bytes_in;
    metrics.bytes_out += bytes_out;
    metrics.packets_in += packets_in;
    metrics.packets_out += packets_out;
    metrics.last_activity = now;
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - metrics.first_seen);
    if (duration.count() > 0) {
        metrics.avg_bandwidth_mbps = static_cast<double>(metrics.bytes_in + metrics.bytes_out) * 8.0 / 
                                     (duration.count() * 1000000.0);
    }
    
    total_bytes_processed_.fetch_add(bytes_in + bytes_out);
    total_packets_processed_.fetch_add(packets_in + packets_out);
}

TrafficMonitor::ClientMetrics TrafficMonitor::get_client_metrics(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(monitor_mutex_);
    
    auto it = client_metrics_.find(client_id);
    if (it != client_metrics_.end()) {
        return it->second;
    }
    
    return ClientMetrics{};
}

uint64_t TrafficMonitor::get_total_bytes() const {
    return total_bytes_processed_.load();
}

uint64_t TrafficMonitor::get_total_packets() const {
    return total_packets_processed_.load();
}

double TrafficMonitor::get_overall_bandwidth_mbps() const {
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - monitor_start_time_);
    
    if (duration.count() > 0) {
        return static_cast<double>(total_bytes_processed_.load()) * 8.0 / (duration.count() * 1000000.0);
    }
    
    return 0.0;
}

SeededRouter::SeededRouter(std::unique_ptr<AdvancedSeedGenerator> seed_generator,
                          std::unique_ptr<IPv6PoolManager> pool_manager)
    : seed_generator_(std::move(seed_generator)), pool_manager_(std::move(pool_manager)),
      failover_enabled_(true), max_routes_per_client_(3) {
    load_balancer_ = std::make_unique<LoadBalancer>();
    nat_table_ = std::make_unique<NAT66Table>();
    traffic_monitor_ = std::make_unique<TrafficMonitor>();
}

SeededRouter::~SeededRouter() = default;

bool SeededRouter::route_packet(const std::string& client_id, const std::vector<uint8_t>& packet,
                                std::string& destination_address) {
    std::lock_guard<std::mutex> lock(router_mutex_);
    
    auto route_it = client_routes_.find(client_id);
    if (route_it == client_routes_.end()) {
        return false;
    }
    
    destination_address = route_it->second->get_current_address();
    if (destination_address.empty()) {
        if (failover_enabled_.load() && route_it->second->try_fallback_address()) {
            destination_address = route_it->second->get_current_address();
        } else {
            return false;
        }
    }
    
    traffic_monitor_->record_traffic(client_id, packet.size(), 0);
    return true;
}

bool SeededRouter::setup_client_routing(const std::string& client_id, const domain::SeedContext& context) {
    std::lock_guard<std::mutex> lock(router_mutex_);
    
    auto addresses = generate_route_addresses(client_id, max_routes_per_client_.load());
    if (addresses.empty()) {
        return false;
    }
    
    client_routes_[client_id] = std::make_unique<SeededRoute>(client_id, addresses);
    return true;
}

std::vector<std::string> SeededRouter::generate_route_addresses(const std::string& client_id, size_t count) {
    std::vector<std::string> addresses;
    
    domain::SeedContext context{};
    context.client_id = client_id;
    context.connection_id = domain::ConnectionId{123};
    
    for (size_t i = 0; i < count; ++i) {
        auto seed_result = seed_generator_->generate(context);
        auto address_result = pool_manager_->allocate(seed_result);
        
        std::ostringstream oss;
        for (size_t j = 0; j < address_result.size(); ++j) {
            if (j > 0 && j % 2 == 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(address_result[j]);
        }
        addresses.push_back(oss.str());
    }
    
    return addresses;
}

void SeededRouter::report_route_success(const std::string& client_id, size_t bytes, double latency) {
    std::lock_guard<std::mutex> lock(router_mutex_);
    
    auto it = client_routes_.find(client_id);
    if (it != client_routes_.end()) {
        it->second->report_success(bytes, latency);
    }
    
    traffic_monitor_->record_traffic(client_id, 0, bytes);
}

void SeededRouter::report_route_failure(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(router_mutex_);
    
    auto it = client_routes_.find(client_id);
    if (it != client_routes_.end()) {
        it->second->report_failure();
    }
}

std::optional<std::string> SeededRouter::get_best_route_for_client(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(router_mutex_);
    
    auto it = client_routes_.find(client_id);
    if (it != client_routes_.end() && it->second->is_healthy()) {
        return it->second->get_current_address();
    }
    
    return load_balancer_->get_best_available_target();
}

size_t SeededRouter::get_active_route_count() const {
    std::lock_guard<std::mutex> lock(router_mutex_);
    return client_routes_.size();
}

size_t SeededRouter::get_nat_session_count() const {
    return nat_table_->get_active_session_count();
}

void SeededRouter::cleanup_inactive_routes(std::chrono::seconds threshold) {
    std::lock_guard<std::mutex> lock(router_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto it = client_routes_.begin();
    
    while (it != client_routes_.end()) {
        auto metrics = it->second->get_metrics();
        if ((now - metrics.last_activity) > threshold) {
            it = client_routes_.erase(it);
        } else {
            ++it;
        }
    }
    
    nat_table_->cleanup_expired_sessions();
}

bool SeededRouter::create_nat_mapping(const std::string& client_id, const std::string& internal_addr, 
                                     uint16_t internal_port, std::string& external_addr, uint16_t& external_port) {
    auto route = get_best_route_for_client(client_id);
    if (!route) return false;
    
    external_addr = *route;
    return nat_table_->create_mapping(internal_addr, internal_port, external_addr, external_port);
}

void SeededRouter::update_route_health() {
    std::lock_guard<std::mutex> lock(router_mutex_);
    
    for (auto& [client_id, route] : client_routes_) {
        if (!route->is_healthy() && failover_enabled_.load()) {
            route->try_fallback_address();
        }
    }
}

void SeededRouter::perform_maintenance() {
    cleanup_inactive_routes(std::chrono::minutes(5));
    update_route_health();
    load_balancer_->cleanup_failed_targets();
}

}
