#include "infrastructure/monitoring_system.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <iomanip>
#include <iostream>
#include <sys/sysinfo.h>
#include <unistd.h>

namespace CipherProxy::Infrastructure {

MetricsCollector& MetricsCollector::instance() {
    static MetricsCollector instance;
    return instance;
}

void MetricsCollector::start_collection() {
    if (collecting_.exchange(true)) {
        return;
    }
    
    collection_thread_ = std::thread(&MetricsCollector::collection_loop, this);
}

void MetricsCollector::stop_collection() {
    if (!collecting_.exchange(false)) {
        return;
    }
    
    if (collection_thread_.joinable()) {
        collection_thread_.join();
    }
}

MetricsCollector::ConnectionMetrics MetricsCollector::get_connection_metrics() const {
    return connection_metrics_;
}

MetricsCollector::SeedMetrics MetricsCollector::get_seed_metrics() const {
    return seed_metrics_;
}

MetricsCollector::IPv6Metrics MetricsCollector::get_ipv6_metrics() const {
    return ipv6_metrics_;
}

MetricsCollector::SecurityMetricsSnapshot MetricsCollector::get_security_metrics() const {
    SecurityMetricsSnapshot metrics;
    metrics.handshakes_completed = security_metrics_.handshakes_completed.load();
    metrics.handshakes_failed = security_metrics_.handshakes_failed.load();
    metrics.key_rotations = security_metrics_.key_rotations.load();
    metrics.encryption_operations = security_metrics_.encryption_operations.load();
    metrics.decryption_operations = security_metrics_.decryption_operations.load();
    metrics.authentication_failures = security_metrics_.authentication_failures.load();
    metrics.replay_attacks_detected = security_metrics_.replay_attacks_detected.load();
    metrics.ddos_attempts_blocked = security_metrics_.ddos_attempts_blocked.load();
    return metrics;
}

MetricsCollector::PerformanceMetricsSnapshot MetricsCollector::get_performance_metrics() const {
    PerformanceMetricsSnapshot metrics;
    metrics.cpu_usage_percent = performance_metrics_.cpu_usage_percent.load();
    metrics.memory_usage_mb = performance_metrics_.memory_usage_mb.load();
    metrics.threads_active = performance_metrics_.threads_active.load();
    metrics.tasks_processed = performance_metrics_.tasks_processed.load();
    metrics.avg_task_time_ms = performance_metrics_.avg_task_time_ms.load();
    metrics.cache_hits = performance_metrics_.cache_hits.load();
    metrics.cache_misses = performance_metrics_.cache_misses.load();
    metrics.network_latency_ms = performance_metrics_.network_latency_ms.load();
    return metrics;
}

void MetricsCollector::record_connection_started() {
    connection_metrics_.total_connections++;
    connection_metrics_.active_connections++;
}

void MetricsCollector::record_connection_ended(std::chrono::milliseconds duration) {
    connection_metrics_.active_connections--;
    
    double duration_ms = duration.count();
    double current_avg = connection_metrics_.avg_connection_duration;
    uint64_t total = connection_metrics_.total_connections;
    double new_avg = (current_avg * (total - 1) + duration_ms) / total;
    connection_metrics_.avg_connection_duration = new_avg;
}

void MetricsCollector::record_connection_failed() {
    connection_metrics_.failed_connections++;
}

void MetricsCollector::record_bytes_transferred(uint64_t sent, uint64_t received) {
    connection_metrics_.total_bytes_sent += sent;
    connection_metrics_.total_bytes_received += received;
}

void MetricsCollector::record_seed_generated(std::chrono::microseconds generation_time) {
    seed_metrics_.seeds_generated++;
    
    double generation_time_ms = generation_time.count() / 1000.0;
    double current_avg = seed_metrics_.avg_seed_generation_time_ms;
    uint64_t total = seed_metrics_.seeds_generated;
    double new_avg = (current_avg * (total - 1) + generation_time_ms) / total;
    
    seed_metrics_.avg_seed_generation_time_ms = new_avg;
}

void MetricsCollector::record_seed_collision() {
    seed_metrics_.seed_collisions++;
}

void MetricsCollector::record_seed_rotation() {
    seed_metrics_.seed_rotations++;
}

void MetricsCollector::record_ipv6_allocation() {
    ipv6_metrics_.addresses_allocated++;
}

void MetricsCollector::record_ipv6_release() {
    ipv6_metrics_.addresses_released++;
}

void MetricsCollector::record_pool_expansion() {
    ipv6_metrics_.pool_expansions++;
}

void MetricsCollector::update_pool_utilization(double percent) {
    ipv6_metrics_.pool_utilization_percent = percent;
}

void MetricsCollector::record_address_conflict() {
    ipv6_metrics_.address_conflicts++;
}

void MetricsCollector::record_handshake_completed() {
    security_metrics_.handshakes_completed.fetch_add(1);
}

void MetricsCollector::record_handshake_failed() {
    security_metrics_.handshakes_failed.fetch_add(1);
}

void MetricsCollector::record_key_rotation() {
    security_metrics_.key_rotations.fetch_add(1);
}

void MetricsCollector::record_encryption_operation() {
    security_metrics_.encryption_operations.fetch_add(1);
}

void MetricsCollector::record_authentication_failure() {
    security_metrics_.authentication_failures.fetch_add(1);
}

void MetricsCollector::record_security_threat(const std::string& threat_type) {
    if (threat_type == "replay_attack") {
        security_metrics_.replay_attacks_detected.fetch_add(1);
    } else if (threat_type == "ddos_attempt") {
        security_metrics_.ddos_attempts_blocked.fetch_add(1);
    }
}

void MetricsCollector::update_system_metrics() {
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        performance_metrics_.memory_usage_mb.store(
            (info.totalram - info.freeram) / (1024 * 1024));
    }
    
    std::ifstream cpuinfo("/proc/loadavg");
    if (cpuinfo.is_open()) {
        double load1, load5, load15;
        cpuinfo >> load1 >> load5 >> load15;
        performance_metrics_.cpu_usage_percent.store(load1 * 10.0);
    }
}

void MetricsCollector::reset_all_metrics() {
    connection_metrics_.reset();
    seed_metrics_.reset();
    ipv6_metrics_.reset();
    security_metrics_.reset();
    performance_metrics_.reset();
}

std::string MetricsCollector::export_metrics_json() const {
    std::ostringstream json;
    
    json << "{\n";
    json << "  \"timestamp\": " << std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() << ",\n";
    
    json << "  \"connections\": {\n";
    json << "    \"total\": " << connection_metrics_.total_connections << ",\n";
    json << "    \"active\": " << connection_metrics_.active_connections << ",\n";
    json << "    \"failed\": " << connection_metrics_.failed_connections << ",\n";
    json << "    \"avg_duration_ms\": " << connection_metrics_.avg_connection_duration << ",\n";
    json << "    \"bytes_sent\": " << connection_metrics_.total_bytes_sent << ",\n";
    json << "    \"bytes_received\": " << connection_metrics_.total_bytes_received << "\n";
    json << "  },\n";
    
    json << "  \"seeds\": {\n";
    json << "    \"generated\": " << seed_metrics_.seeds_generated << ",\n";
    json << "    \"collisions\": " << seed_metrics_.seed_collisions << ",\n";
    json << "    \"rotations\": " << seed_metrics_.seed_rotations << ",\n";
    json << "    \"avg_generation_time_ms\": " << seed_metrics_.avg_seed_generation_time_ms << "\n";
    json << "  },\n";
    
    json << "  \"ipv6\": {\n";
    json << "    \"allocated\": " << ipv6_metrics_.addresses_allocated << ",\n";
    json << "    \"released\": " << ipv6_metrics_.addresses_released << ",\n";
    json << "    \"pool_utilization_percent\": " << ipv6_metrics_.pool_utilization_percent << ",\n";
    json << "    \"conflicts\": " << ipv6_metrics_.address_conflicts << "\n";
    json << "  },\n";
    
    json << "  \"security\": {\n";
    json << "    \"handshakes_completed\": " << security_metrics_.handshakes_completed.load() << ",\n";
    json << "    \"handshakes_failed\": " << security_metrics_.handshakes_failed.load() << ",\n";
    json << "    \"authentication_failures\": " << security_metrics_.authentication_failures.load() << ",\n";
    json << "    \"replay_attacks_detected\": " << security_metrics_.replay_attacks_detected.load() << "\n";
    json << "  },\n";
    
    json << "  \"performance\": {\n";
    json << "    \"cpu_usage_percent\": " << performance_metrics_.cpu_usage_percent.load() << ",\n";
    json << "    \"memory_usage_mb\": " << performance_metrics_.memory_usage_mb.load() << ",\n";
    json << "    \"threads_active\": " << performance_metrics_.threads_active.load() << "\n";
    json << "  }\n";
    json << "}";
    
    return json.str();
}

std::string MetricsCollector::export_metrics_prometheus() const {
    std::ostringstream metrics;
    
    metrics << "# HELP vpn_connections_total Total number of VPN connections\n";
    metrics << "# TYPE vpn_connections_total counter\n";
    metrics << "vpn_connections_total " << connection_metrics_.total_connections << "\n\n";
    
    metrics << "# HELP vpn_connections_active Current active VPN connections\n";
    metrics << "# TYPE vpn_connections_active gauge\n";
    metrics << "vpn_connections_active " << connection_metrics_.active_connections << "\n\n";
    
    metrics << "# HELP vpn_seeds_generated_total Total number of seeds generated\n";
    metrics << "# TYPE vpn_seeds_generated_total counter\n";
    metrics << "vpn_seeds_generated_total " << seed_metrics_.seeds_generated << "\n\n";
    
    metrics << "# HELP vpn_ipv6_pool_utilization IPv6 address pool utilization percentage\n";
    metrics << "# TYPE vpn_ipv6_pool_utilization gauge\n";
    metrics << "vpn_ipv6_pool_utilization " << ipv6_metrics_.pool_utilization_percent << "\n\n";
    
    metrics << "# HELP vpn_security_handshakes_total Total completed handshakes\n";
    metrics << "# TYPE vpn_security_handshakes_total counter\n";
    metrics << "vpn_security_handshakes_total " << security_metrics_.handshakes_completed.load() << "\n\n";
    
    return metrics.str();
}

void MetricsCollector::collection_loop() {
    while (collecting_.load()) {
        update_system_metrics();
        update_derived_metrics();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void MetricsCollector::update_derived_metrics() {
    uint64_t total_bytes = connection_metrics_.total_bytes_sent + 
                          connection_metrics_.total_bytes_received;
    double bandwidth_mbps = (total_bytes * 8.0) / (1024.0 * 1024.0 * 5.0);
    connection_metrics_.avg_bandwidth_mbps = bandwidth_mbps;
}

HealthMonitor& HealthMonitor::instance() {
    static HealthMonitor instance;
    return instance;
}

void HealthMonitor::start_monitoring() {
    if (monitoring_.exchange(true)) {
        return;
    }
    
    register_health_check("network_interfaces", [this] { return check_network_interfaces(); });
    register_health_check("ipv6_pool", [this] { return check_ipv6_pool(); });
    register_health_check("system_resources", [this] { return check_system_resources(); });
    register_health_check("connections", [this] { return check_connection_health(); });
    register_health_check("security", [this] { return check_security_status(); });
    
    monitor_thread_ = std::thread(&HealthMonitor::monitoring_loop, this);
}

void HealthMonitor::stop_monitoring() {
    if (!monitoring_.exchange(false)) {
        return;
    }
    
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void HealthMonitor::register_health_check(const std::string& component_name, HealthCheckFunction check_func) {
    std::unique_lock<std::shared_mutex> lock(health_mutex_);
    health_checks_[component_name] = check_func;
}

void HealthMonitor::unregister_health_check(const std::string& component_name) {
    std::unique_lock<std::shared_mutex> lock(health_mutex_);
    health_checks_.erase(component_name);
    component_status_.erase(component_name);
}

HealthMonitor::SystemHealth HealthMonitor::get_system_health() const {
    std::shared_lock<std::shared_mutex> lock(health_mutex_);
    
    SystemHealth system_health;
    system_health.timestamp = std::chrono::steady_clock::now();
    system_health.overall_status = determine_overall_status();
    
    for (const auto& [component, status] : component_status_) {
        system_health.components.push_back(status);
    }
    
    size_t healthy_count = std::count_if(system_health.components.begin(), 
                                        system_health.components.end(),
                                        [](const ComponentHealth& comp) {
                                            return comp.status == ComponentStatus::HEALTHY;
                                        });
    
    system_health.summary = std::to_string(healthy_count) + "/" + 
                           std::to_string(system_health.components.size()) + " components healthy";
    
    return system_health;
}

HealthMonitor::ComponentHealth HealthMonitor::get_component_health(const std::string& component_name) const {
    std::shared_lock<std::shared_mutex> lock(health_mutex_);
    
    auto it = component_status_.find(component_name);
    if (it != component_status_.end()) {
        return it->second;
    }
    
    return ComponentHealth{ComponentStatus::UNKNOWN, component_name, "component not found", 
                          std::chrono::steady_clock::now(), {}};
}

void HealthMonitor::set_check_interval(std::chrono::seconds interval) {
    check_interval_ = interval;
}

void HealthMonitor::force_health_check() {
    run_health_checks();
}

bool HealthMonitor::is_system_healthy() const {
    return determine_overall_status() == ComponentStatus::HEALTHY;
}

std::vector<std::string> HealthMonitor::get_unhealthy_components() const {
    std::shared_lock<std::shared_mutex> lock(health_mutex_);
    
    std::vector<std::string> unhealthy;
    for (const auto& [component, status] : component_status_) {
        if (status.status != ComponentStatus::HEALTHY) {
            unhealthy.push_back(component);
        }
    }
    
    return unhealthy;
}

void HealthMonitor::monitoring_loop() {
    while (monitoring_.load()) {
        run_health_checks();
        std::this_thread::sleep_for(check_interval_);
    }
}

void HealthMonitor::run_health_checks() {
    std::shared_lock<std::shared_mutex> read_lock(health_mutex_);
    auto checks = health_checks_;
    read_lock.unlock();
    
    std::unordered_map<std::string, ComponentHealth> new_status;
    
    for (const auto& [component, check_func] : checks) {
        try {
            new_status[component] = check_func();
        } catch (const std::exception& e) {
            new_status[component] = ComponentHealth{
                ComponentStatus::CRITICAL, component, 
                "health check failed: " + std::string(e.what()),
                std::chrono::steady_clock::now(), {}
            };
        }
    }
    
    std::unique_lock<std::shared_mutex> write_lock(health_mutex_);
    component_status_ = std::move(new_status);
}

HealthMonitor::ComponentStatus HealthMonitor::determine_overall_status() const {
    if (component_status_.empty()) {
        return ComponentStatus::UNKNOWN;
    }
    
    bool has_critical = false;
    bool has_warning = false;
    
    for (const auto& [component, status] : component_status_) {
        if (status.status == ComponentStatus::CRITICAL) {
            has_critical = true;
        } else if (status.status == ComponentStatus::WARNING) {
            has_warning = true;
        }
    }
    
    if (has_critical) return ComponentStatus::CRITICAL;
    if (has_warning) return ComponentStatus::WARNING;
    return ComponentStatus::HEALTHY;
}

HealthMonitor::ComponentHealth HealthMonitor::check_network_interfaces() {
    ComponentHealth health;
    health.component_name = "network_interfaces";
    health.last_check = std::chrono::steady_clock::now();
    
    std::ifstream interfaces("/proc/net/dev");
    if (!interfaces.is_open()) {
        health.status = ComponentStatus::CRITICAL;
        health.status_message = "cannot read network interfaces";
        return health;
    }
    
    health.status = ComponentStatus::HEALTHY;
    health.status_message = "network interfaces operational";
    return health;
}

HealthMonitor::ComponentHealth HealthMonitor::check_ipv6_pool() {
    ComponentHealth health;
    health.component_name = "ipv6_pool";
    health.last_check = std::chrono::steady_clock::now();
    
    const auto& metrics = MetricsCollector::instance().get_ipv6_metrics();
    double utilization = metrics.pool_utilization_percent;
    
    if (utilization > 90.0) {
        health.status = ComponentStatus::CRITICAL;
        health.status_message = "ipv6 pool utilization critical: " + std::to_string(utilization) + "%";
    } else if (utilization > 75.0) {
        health.status = ComponentStatus::WARNING;
        health.status_message = "ipv6 pool utilization high: " + std::to_string(utilization) + "%";
    } else {
        health.status = ComponentStatus::HEALTHY;
        health.status_message = "ipv6 pool utilization normal: " + std::to_string(utilization) + "%";
    }
    
    health.details["utilization_percent"] = std::to_string(utilization);
    health.details["allocated"] = std::to_string(metrics.addresses_allocated);
    health.details["conflicts"] = std::to_string(metrics.address_conflicts);
    
    return health;
}

HealthMonitor::ComponentHealth HealthMonitor::check_system_resources() {
    ComponentHealth health;
    health.component_name = "system_resources";
    health.last_check = std::chrono::steady_clock::now();
    
    const auto& perf_metrics = MetricsCollector::instance().get_performance_metrics();
    double cpu_usage = perf_metrics.cpu_usage_percent;
    uint64_t memory_mb = perf_metrics.memory_usage_mb;
    
    if (cpu_usage > 90.0 || memory_mb > 8192) {
        health.status = ComponentStatus::CRITICAL;
        health.status_message = "system resources critical";
    } else if (cpu_usage > 75.0 || memory_mb > 4096) {
        health.status = ComponentStatus::WARNING;
        health.status_message = "system resources high";
    } else {
        health.status = ComponentStatus::HEALTHY;
        health.status_message = "system resources normal";
    }
    
    health.details["cpu_usage_percent"] = std::to_string(cpu_usage);
    health.details["memory_usage_mb"] = std::to_string(memory_mb);
    
    return health;
}

HealthMonitor::ComponentHealth HealthMonitor::check_connection_health() {
    ComponentHealth health;
    health.component_name = "connections";
    health.last_check = std::chrono::steady_clock::now();
    
    const auto& conn_metrics = MetricsCollector::instance().get_connection_metrics();
    uint64_t active = conn_metrics.active_connections;
    uint64_t failed = conn_metrics.failed_connections;
    uint64_t total = conn_metrics.total_connections;
    
    double failure_rate = total > 0 ? (static_cast<double>(failed) / total) * 100.0 : 0.0;
    
    if (failure_rate > 20.0) {
        health.status = ComponentStatus::CRITICAL;
        health.status_message = "high connection failure rate: " + std::to_string(failure_rate) + "%";
    } else if (failure_rate > 10.0) {
        health.status = ComponentStatus::WARNING;
        health.status_message = "elevated connection failure rate: " + std::to_string(failure_rate) + "%";
    } else {
        health.status = ComponentStatus::HEALTHY;
        health.status_message = "connection health normal";
    }
    
    health.details["active_connections"] = std::to_string(active);
    health.details["failure_rate_percent"] = std::to_string(failure_rate);
    
    return health;
}

HealthMonitor::ComponentHealth HealthMonitor::check_security_status() {
    ComponentHealth health;
    health.component_name = "security";
    health.last_check = std::chrono::steady_clock::now();
    
    const auto& sec_metrics = MetricsCollector::instance().get_security_metrics();
    uint64_t auth_failures = sec_metrics.authentication_failures;
    uint64_t replay_attacks = sec_metrics.replay_attacks_detected;
    uint64_t ddos_attempts = sec_metrics.ddos_attempts_blocked;
    
    uint64_t total_threats = auth_failures + replay_attacks + ddos_attempts;
    
    if (total_threats > 100) {
        health.status = ComponentStatus::CRITICAL;
        health.status_message = "high security threat activity";
    } else if (total_threats > 50) {
        health.status = ComponentStatus::WARNING;
        health.status_message = "elevated security threat activity";
    } else {
        health.status = ComponentStatus::HEALTHY;
        health.status_message = "security status normal";
    }
    
    health.details["auth_failures"] = std::to_string(auth_failures);
    health.details["replay_attacks"] = std::to_string(replay_attacks);
    health.details["ddos_attempts"] = std::to_string(ddos_attempts);
    
    return health;
}

AlertManager& AlertManager::instance() {
    static AlertManager instance;
    return instance;
}

void AlertManager::start() {
    if (running_.exchange(true)) {
        return;
    }
    
    alert_thread_ = std::thread(&AlertManager::alert_processing_loop, this);
}

void AlertManager::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(alert_mutex_);
        running_ = false;
    }
    alert_condition_.notify_all();
    if (alert_thread_.joinable()) {
        alert_thread_.join();
    }
}

void AlertManager::register_handler(AlertSeverity severity, AlertHandler handler) {
    std::unique_lock<std::shared_mutex> lock(handlers_mutex_);
    handlers_[severity].push_back(handler);
}

void AlertManager::create_alert(AlertSeverity severity, const std::string& component,
                             const std::string& message, const std::unordered_map<std::string, std::string>& metadata) {
    Alert alert;
    alert.id = generate_alert_id();
    alert.severity = severity;
    alert.component = component;
    alert.message = message;
    alert.timestamp = std::chrono::steady_clock::now();
    alert.metadata = metadata;
    
    {
        std::unique_lock<std::shared_mutex> lock(alerts_mutex_);
        active_alerts_.push_back(alert);
    }
    
    alert_condition_.notify_one();
}

void AlertManager::acknowledge_alert(const std::string& alert_id) {
    std::unique_lock<std::shared_mutex> lock(alerts_mutex_);
    for (auto& alert : active_alerts_) {
        if (alert.id == alert_id) {
            alert.acknowledged = true;
            break;
        }
    }
}

void AlertManager::resolve_alert(const std::string& alert_id) {
    std::unique_lock<std::shared_mutex> lock(alerts_mutex_);
    active_alerts_.erase(
        std::remove_if(active_alerts_.begin(), active_alerts_.end(),
            [&alert_id](const Alert& alert) { return alert.id == alert_id; }),
        active_alerts_.end()
    );
}
}

namespace CipherProxy::Infrastructure {

std::vector<AlertManager::Alert> AlertManager::get_active_alerts() const {
    std::shared_lock<std::shared_mutex> lock(alerts_mutex_);
    std::vector<AlertManager::Alert> alerts;
    for (const auto& alert : active_alerts_) {
        alerts.push_back(alert);
    }
    return alerts;
}

std::vector<AlertManager::Alert> AlertManager::get_alerts_by_severity(AlertManager::AlertSeverity severity) const {
    std::shared_lock<std::shared_mutex> lock(alerts_mutex_);
    std::vector<AlertManager::Alert> filtered_alerts;
    for (const auto& alert : active_alerts_) {
        if (alert.severity == severity) {
            filtered_alerts.push_back(alert);
        }
    }
    return filtered_alerts;
}

} // namespace CipherProxy::Infrastructure

using CipherProxy::Infrastructure::Logger;

namespace CipherProxy::Infrastructure {

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

void Logger::initialize(LogLevel min_level) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    min_level_ = min_level;
    running_ = true;
    if (!writer_thread_.joinable()) {
        writer_thread_ = std::thread(&Logger::writer_loop, this);
    }
}

void Logger::shutdown() {
    running_ = false;
    if (writer_thread_.joinable()) {
        writer_thread_.join();
    }
}

void Logger::set_log_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    min_level_ = level;
}

void Logger::set_log_file(const std::string& filename) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_file_ = filename;
}

void Logger::set_max_file_size(size_t max_size_mb) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    max_file_size_mb_ = max_size_mb;
}

void Logger::set_max_files(size_t max_files) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    max_files_ = max_files;
}

void Logger::enable_console_output(bool enable) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    console_output_ = enable;
}

void Logger::enable_json_format(bool enable) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    json_format_ = enable;
}

void Logger::log(LogLevel level, const std::string& component, const std::string& message,
                 const std::unordered_map<std::string, std::string>& metadata) {
    if (level < min_level_) return;
    LogEntry entry{level, component, message, std::chrono::steady_clock::now(), metadata, std::this_thread::get_id()};
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_buffer_.push(entry);
    }
}

void Logger::trace(const std::string& component, const std::string& message, const std::unordered_map<std::string, std::string>& metadata) {
    log(LogLevel::TRACE, component, message, metadata);
}
void Logger::debug(const std::string& component, const std::string& message, const std::unordered_map<std::string, std::string>& metadata) {
    log(LogLevel::DEBUG_LEVEL, component, message, metadata);
}
void Logger::info(const std::string& component, const std::string& message, const std::unordered_map<std::string, std::string>& metadata) {
    log(LogLevel::INFO, component, message, metadata);
}
void Logger::warning(const std::string& component, const std::string& message, const std::unordered_map<std::string, std::string>& metadata) {
    log(LogLevel::WARNING, component, message, metadata);
}
void Logger::error(const std::string& component, const std::string& message, const std::unordered_map<std::string, std::string>& metadata) {
    log(LogLevel::ERROR, component, message, metadata);
}
void Logger::critical(const std::string& component, const std::string& message, const std::unordered_map<std::string, std::string>& metadata) {
    log(LogLevel::CRITICAL, component, message, metadata);
}

void Logger::log_connection_event(const std::string& client_id, const std::string& event, const std::unordered_map<std::string, std::string>& details) {
    std::unordered_map<std::string, std::string> enriched_details = details;
    enriched_details["client_id"] = client_id;
    enriched_details["timestamp"] = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    log(LogLevel::INFO, "connection", event, enriched_details);
}
void Logger::log_security_event(const std::string& event_type, const std::string& details, const std::unordered_map<std::string, std::string>& metadata) {
    log(LogLevel::WARNING, event_type, details, metadata);
}
void Logger::log_performance_event(const std::string& metric_name, double value, const std::unordered_map<std::string, std::string>& metadata) {
    log(LogLevel::INFO, metric_name, std::to_string(value), metadata);
}

std::vector<Logger::LogEntry> Logger::get_recent_logs(size_t count) const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::vector<LogEntry> logs;
    std::queue<LogEntry> buffer_copy = log_buffer_;
    while (!buffer_copy.empty() && logs.size() < count) {
        logs.push_back(buffer_copy.front());
        buffer_copy.pop();
    }
    return logs;
}

std::vector<Logger::LogEntry> Logger::get_logs_by_level(LogLevel level, size_t count) const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::vector<LogEntry> logs;
    std::queue<LogEntry> buffer_copy = log_buffer_;
    while (!buffer_copy.empty() && logs.size() < count) {
        if (buffer_copy.front().level == level) {
            logs.push_back(buffer_copy.front());
        }
        buffer_copy.pop();
    }
    return logs;
}

std::vector<Logger::LogEntry> Logger::get_logs_by_component(const std::string& component, size_t count) const {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::vector<LogEntry> logs;
    std::queue<LogEntry> buffer_copy = log_buffer_;
    while (!buffer_copy.empty() && logs.size() < count) {
        if (buffer_copy.front().component == component) {
            logs.push_back(buffer_copy.front());
        }
        buffer_copy.pop();
    }
    return logs;
}

void Logger::writer_loop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::lock_guard<std::mutex> lock(log_mutex_);
        while (!log_buffer_.empty()) {
            const auto& entry = log_buffer_.front();
            write_to_file(entry);
            if (console_output_) write_to_console(entry);
            log_buffer_.pop();
        }
    }
}

void Logger::write_to_file(const LogEntry& entry) {
    if (log_file_.empty()) return;
    std::ofstream ofs(log_file_, std::ios::app);
    if (!ofs.is_open()) return;
    ofs << format_log_entry(entry) << std::endl;
}

void Logger::write_to_console(const LogEntry& entry) {
    std::cout << format_log_entry(entry) << std::endl;
}

void Logger::rotate_log_files() {
    // Implement rotation logic if needed
}

std::string Logger::format_log_entry(const LogEntry& entry) const {
    return json_format_ ? format_json_entry(entry) : log_level_to_string(entry.level) + " [" + entry.component + "] " + entry.message;
}

std::string Logger::format_json_entry(const LogEntry& entry) const {
    std::ostringstream oss;
    oss << "{\"level\":\"" << log_level_to_string(entry.level) << "\",";
    oss << "\"component\":\"" << entry.component << "\",";
    oss << "\"message\":\"" << entry.message << "\"}";
    return oss.str();
}

std::string Logger::log_level_to_string(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG_LEVEL: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

MonitoringManager& MonitoringManager::instance() {
    static MonitoringManager instance;
    return instance;
}

void MonitoringManager::initialize() {
    if (initialized_.exchange(true)) {
        return;
    }
    
    startup_time_ = std::chrono::steady_clock::now();
    configure_logging();
    
    MetricsCollector::instance().start_collection();
    HealthMonitor::instance().start_monitoring();
    AlertManager::instance().start();
    
    setup_metric_based_alerts();
    setup_health_based_alerts();
    setup_default_health_checks();
    configure_alert_thresholds();
}

void MonitoringManager::shutdown() {
    if (!initialized_.exchange(false)) {
        return;
    }
    
    AlertManager::instance().stop();
    HealthMonitor::instance().stop_monitoring();
    MetricsCollector::instance().stop_collection();
}

MetricsCollector& MonitoringManager::get_metrics_collector() {
    return MetricsCollector::instance();
}

HealthMonitor& MonitoringManager::get_health_monitor() {
    return HealthMonitor::instance();
}

AlertManager& MonitoringManager::get_alert_manager() {
    return AlertManager::instance();
}

Logger& MonitoringManager::get_logger() {
    return Logger::instance();
}

void MonitoringManager::start_all_monitoring() {
    MetricsCollector::instance().start_collection();
    HealthMonitor::instance().start_monitoring();
    AlertManager::instance().start();
}

void MonitoringManager::stop_all_monitoring() {
    AlertManager::instance().stop();
    HealthMonitor::instance().stop_monitoring();
    MetricsCollector::instance().stop_collection();
}

MonitoringManager::MonitoringStatus MonitoringManager::get_status() const {
    MonitoringStatus status;
    status.metrics_collecting = true;
    status.health_monitoring = true;
    status.alerts_active = true;
    status.logging_active = true;
    status.startup_time = startup_time_;
    return status;
}

void MonitoringManager::export_dashboard_data(const std::string& output_file) const {
    std::ofstream file(output_file);
    if (!file.is_open()) {
        return;
    }
    
    auto metrics = MetricsCollector::instance().export_metrics_json();
    file << metrics;
}

void MonitoringManager::generate_health_report(const std::string& output_file) const {
    std::ofstream file(output_file);
    if (!file.is_open()) {
        return;
    }
    
    auto health = HealthMonitor::instance().get_system_health();
    file << "System Health Report\\n";
    file << "Status: " << static_cast<int>(health.overall_status) << "\\n";
    file << "Summary: " << health.summary << "\\n";
}

void MonitoringManager::configure_alert_thresholds() {
    // Implementation for alert threshold configuration
}

void MonitoringManager::setup_default_health_checks() {
    // Implementation for default health checks setup
}

void MonitoringManager::setup_metric_based_alerts() {
    // Implementation for metric-based alerts
}

void MonitoringManager::setup_health_based_alerts() {
    // Implementation for health-based alerts  
}

void MonitoringManager::configure_logging() {
    Logger::instance().initialize(Logger::LogLevel::INFO);
}

void AlertManager::alert_processing_loop() {
    while (running_) {
        std::unique_lock<std::mutex> lock(alert_mutex_);
        alert_condition_.wait(lock, [this] { return !running_ || !active_alerts_.empty(); });
        
        if (!running_) break;
        
        for (const auto& alert : active_alerts_) {
            if (!alert.acknowledged) {
                notify_handlers(alert);
            }
        }
        
        lock.unlock();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

std::string AlertManager::generate_alert_id() const {
    static std::atomic<uint64_t> counter{0};
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return "alert_" + std::to_string(timestamp) + "_" + std::to_string(++counter);
}

void AlertManager::notify_handlers(const Alert& alert) {
    for (const auto& handler : alert_handlers_) {
        try {
            handler(alert);
        } catch (const std::exception& e) {
            // Log handler error but continue
        }
    }
}

} // namespace CipherProxy::Infrastructure
