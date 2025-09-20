#pragma once

#include <chrono>
#include <atomic>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <functional>
#include <queue>

namespace CipherProxy::Infrastructure {

class MetricsCollector {
public:
    struct ConnectionMetrics {
        uint64_t total_connections{0};
        uint64_t active_connections{0};
        uint64_t failed_connections{0};
        uint64_t dropped_connections{0};
        double avg_connection_duration{0.0};
        uint64_t total_bytes_sent{0};
        uint64_t total_bytes_received{0};
        double avg_bandwidth_mbps{0.0};
        
        void reset() {
            total_connections = 0;
            active_connections = 0;
            failed_connections = 0;
            dropped_connections = 0;
            avg_connection_duration = 0.0;
            total_bytes_sent = 0;
            total_bytes_received = 0;
            avg_bandwidth_mbps = 0.0;
        }
    };
    
    struct SeedMetrics {
        uint64_t seeds_generated{0};
        uint64_t seed_collisions{0};
        uint64_t seed_rotations{0};
        double avg_seed_generation_time_ms{0.0};
        uint64_t active_seeds{0};
        uint64_t expired_seeds{0};
        
        void reset() {
            seeds_generated = 0;
            seed_collisions = 0;
            seed_rotations = 0;
            avg_seed_generation_time_ms = 0.0;
            active_seeds = 0;
            expired_seeds = 0;
        }
    };
    
    struct IPv6Metrics {
        uint64_t addresses_allocated{0};
        uint64_t addresses_released{0};
        uint64_t pool_expansions{0};
        double pool_utilization_percent{0.0};
        uint64_t address_conflicts{0};
        uint64_t failed_allocations{0};
        
        void reset() {
            addresses_allocated = 0;
            addresses_released = 0;
            pool_expansions = 0;
            pool_utilization_percent = 0.0;
            address_conflicts = 0;
            failed_allocations = 0;
        }
    };
    
    struct SecurityMetrics {
        std::atomic<uint64_t> handshakes_completed{0};
        std::atomic<uint64_t> handshakes_failed{0};
        std::atomic<uint64_t> key_rotations{0};
        std::atomic<uint64_t> encryption_operations{0};
        std::atomic<uint64_t> decryption_operations{0};
        std::atomic<uint64_t> authentication_failures{0};
        std::atomic<uint64_t> replay_attacks_detected{0};
        std::atomic<uint64_t> ddos_attempts_blocked{0};
        
        void reset() {
            handshakes_completed = 0;
            handshakes_failed = 0;
            key_rotations = 0;
            encryption_operations = 0;
            decryption_operations = 0;
            authentication_failures = 0;
            replay_attacks_detected = 0;
            ddos_attempts_blocked = 0;
        }
    };
    
    struct SecurityMetricsSnapshot {
        uint64_t handshakes_completed;
        uint64_t handshakes_failed;
        uint64_t key_rotations;
        uint64_t encryption_operations;
        uint64_t decryption_operations;
        uint64_t authentication_failures;
        uint64_t replay_attacks_detected;
        uint64_t ddos_attempts_blocked;
    };
    
    struct PerformanceMetrics {
        std::atomic<double> cpu_usage_percent{0.0};
        std::atomic<uint64_t> memory_usage_mb{0};
        std::atomic<uint64_t> threads_active{0};
        std::atomic<uint64_t> tasks_processed{0};
        std::atomic<double> avg_task_time_ms{0.0};
        std::atomic<uint64_t> cache_hits{0};
        std::atomic<uint64_t> cache_misses{0};
        std::atomic<double> network_latency_ms{0.0};
        
        void reset() {
            cpu_usage_percent = 0.0;
            memory_usage_mb = 0;
            threads_active = 0;
            tasks_processed = 0;
            avg_task_time_ms = 0.0;
            cache_hits = 0;
            cache_misses = 0;
            network_latency_ms = 0.0;
        }
    };
    
    struct PerformanceMetricsSnapshot {
        double cpu_usage_percent;
        uint64_t memory_usage_mb;
        uint64_t threads_active;
        uint64_t tasks_processed;
        double avg_task_time_ms;
        uint64_t cache_hits;
        uint64_t cache_misses;
        double network_latency_ms;
    };
    
    static MetricsCollector& instance();
    
    void start_collection();
    void stop_collection();
    
    ConnectionMetrics get_connection_metrics() const;
    SeedMetrics get_seed_metrics() const;
    IPv6Metrics get_ipv6_metrics() const;
    SecurityMetricsSnapshot get_security_metrics() const;
    PerformanceMetricsSnapshot get_performance_metrics() const;
    
    void record_connection_started();
    void record_connection_ended(std::chrono::milliseconds duration);
    void record_connection_failed();
    void record_bytes_transferred(uint64_t sent, uint64_t received);
    
    void record_seed_generated(std::chrono::microseconds generation_time);
    void record_seed_collision();
    void record_seed_rotation();
    
    void record_ipv6_allocation();
    void record_ipv6_release();
    void record_pool_expansion();
    void update_pool_utilization(double percent);
    void record_address_conflict();
    
    void record_handshake_completed();
    void record_handshake_failed();
    void record_key_rotation();
    void record_encryption_operation();
    void record_authentication_failure();
    void record_security_threat(const std::string& threat_type);
    
    void update_system_metrics();
    void reset_all_metrics();
    
    std::string export_metrics_json() const;
    std::string export_metrics_prometheus() const;

private:
    MetricsCollector() = default;
    
    ConnectionMetrics connection_metrics_;
    SeedMetrics seed_metrics_;
    IPv6Metrics ipv6_metrics_;
    SecurityMetrics security_metrics_;
    PerformanceMetrics performance_metrics_;
    
    std::atomic<bool> collecting_{false};
    std::thread collection_thread_;
    
    void collection_loop();
    void update_derived_metrics();
};

class HealthMonitor {
public:
    enum class ComponentStatus {
        HEALTHY,
        WARNING,
        CRITICAL,
        UNKNOWN
    };
    
    struct ComponentHealth {
        ComponentStatus status;
        std::string component_name;
        std::string status_message;
        std::chrono::steady_clock::time_point last_check;
        std::unordered_map<std::string, std::string> details;
    };
    
    struct SystemHealth {
        ComponentStatus overall_status;
        std::vector<ComponentHealth> components;
        std::chrono::steady_clock::time_point timestamp;
        std::string summary;
    };
    
    using HealthCheckFunction = std::function<ComponentHealth()>;
    
    static HealthMonitor& instance();
    
    void start_monitoring();
    void stop_monitoring();
    
    void register_health_check(const std::string& component_name, HealthCheckFunction check_func);
    void unregister_health_check(const std::string& component_name);
    
    SystemHealth get_system_health() const;
    ComponentHealth get_component_health(const std::string& component_name) const;
    
    void set_check_interval(std::chrono::seconds interval);
    void force_health_check();
    
    bool is_system_healthy() const;
    std::vector<std::string> get_unhealthy_components() const;

private:
    HealthMonitor() = default;
    
    mutable std::shared_mutex health_mutex_;
    std::unordered_map<std::string, HealthCheckFunction> health_checks_;
    std::unordered_map<std::string, ComponentHealth> component_status_;
    
    std::atomic<bool> monitoring_{false};
    std::thread monitor_thread_;
    std::chrono::seconds check_interval_{30};
    
    void monitoring_loop();
    void run_health_checks();
    ComponentStatus determine_overall_status() const;
    
    ComponentHealth check_network_interfaces();
    ComponentHealth check_ipv6_pool();
    ComponentHealth check_system_resources();
    ComponentHealth check_connection_health();
    ComponentHealth check_security_status();
};

class AlertManager {
public:
    enum class AlertSeverity {
        INFO,
        WARNING,
        CRITICAL
    };
    
    struct Alert {
        std::string id;
        AlertSeverity severity;
        std::string component;
        std::string message;
        std::chrono::steady_clock::time_point timestamp;
        std::unordered_map<std::string, std::string> metadata;
        bool acknowledged;
    };
    
    using AlertHandler = std::function<void(const Alert&)>;
    
    static AlertManager& instance();
    
    void start();
    void stop();
    
    void register_alert_handler(AlertHandler handler);
    void register_handler(AlertSeverity severity, AlertHandler handler);
    void create_alert(AlertSeverity severity, const std::string& component, 
                     const std::string& message, 
                     const std::unordered_map<std::string, std::string>& metadata = {});
    
    void acknowledge_alert(const std::string& alert_id);
    void resolve_alert(const std::string& alert_id);
    
    std::vector<Alert> get_active_alerts() const;
    std::vector<Alert> get_alerts_by_severity(AlertSeverity severity) const;
    std::vector<Alert> get_alerts_by_component(const std::string& component) const;
    
    void clear_acknowledged_alerts();
    void set_alert_retention(std::chrono::hours retention);

private:
    AlertManager() = default;
    
    mutable std::shared_mutex alerts_mutex_;
    std::vector<Alert> active_alerts_;
    std::vector<AlertHandler> alert_handlers_;
    std::unordered_map<AlertSeverity, std::vector<AlertHandler>> handlers_;
    mutable std::shared_mutex handlers_mutex_;
    
    std::atomic<bool> running_{false};
    std::thread cleanup_thread_;
    std::thread alert_thread_;
    std::condition_variable alert_condition_;
    mutable std::mutex alert_mutex_;
    std::chrono::hours alert_retention_{24};
    
    std::string generate_alert_id() const;
    void cleanup_old_alerts();
    void notify_handlers(const Alert& alert);
    void alert_processing_loop();
};

class Logger {
public:
    enum class LogLevel {
        TRACE,
        DEBUG_LEVEL,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };
    
    struct LogEntry {
        LogLevel level;
        std::string component;
        std::string message;
        std::chrono::steady_clock::time_point timestamp;
        std::unordered_map<std::string, std::string> metadata;
        std::thread::id thread_id;
    };
    
    static Logger& instance();
    
    void initialize(LogLevel min_level = LogLevel::INFO);
    void shutdown();
    
    void set_log_level(LogLevel level);
    void set_log_file(const std::string& filename);
    void set_max_file_size(size_t max_size_mb);
    void set_max_files(size_t max_files);
    void enable_console_output(bool enable);
    void enable_json_format(bool enable);
    
    void log(LogLevel level, const std::string& component, const std::string& message,
             const std::unordered_map<std::string, std::string>& metadata = {});
    
    void trace(const std::string& component, const std::string& message, 
               const std::unordered_map<std::string, std::string>& metadata = {});
    void debug(const std::string& component, const std::string& message,
               const std::unordered_map<std::string, std::string>& metadata = {});
    void info(const std::string& component, const std::string& message,
              const std::unordered_map<std::string, std::string>& metadata = {});
    void warning(const std::string& component, const std::string& message,
                 const std::unordered_map<std::string, std::string>& metadata = {});
    void error(const std::string& component, const std::string& message,
               const std::unordered_map<std::string, std::string>& metadata = {});
    void critical(const std::string& component, const std::string& message,
                  const std::unordered_map<std::string, std::string>& metadata = {});
    
    void log_connection_event(const std::string& client_id, const std::string& event,
                             const std::unordered_map<std::string, std::string>& details = {});
    void log_security_event(const std::string& event_type, const std::string& details,
                           const std::unordered_map<std::string, std::string>& metadata = {});
    void log_performance_event(const std::string& metric_name, double value,
                              const std::unordered_map<std::string, std::string>& metadata = {});
    
    std::vector<LogEntry> get_recent_logs(size_t count = 100) const;
    std::vector<LogEntry> get_logs_by_level(LogLevel level, size_t count = 100) const;
    std::vector<LogEntry> get_logs_by_component(const std::string& component, size_t count = 100) const;

private:
    Logger() = default;
    
    LogLevel min_level_{LogLevel::INFO};
    std::string log_file_;
    size_t max_file_size_mb_{100};
    size_t max_files_{10};
    bool console_output_{true};
    bool json_format_{false};
    
    mutable std::mutex log_mutex_;
    std::queue<LogEntry> log_buffer_;
    std::atomic<bool> running_{false};
    std::thread writer_thread_;
    
    void writer_loop();
    void write_to_file(const LogEntry& entry);
    void write_to_console(const LogEntry& entry);
    void rotate_log_files();
    
    std::string format_log_entry(const LogEntry& entry) const;
    std::string format_json_entry(const LogEntry& entry) const;
    std::string log_level_to_string(LogLevel level) const;
};

class MonitoringManager {
public:
    static MonitoringManager& instance();
    
    void initialize();
    void shutdown();
    
    MetricsCollector& get_metrics_collector();
    HealthMonitor& get_health_monitor();
    AlertManager& get_alert_manager();
    Logger& get_logger();
    
    void start_all_monitoring();
    void stop_all_monitoring();
    
    struct MonitoringStatus {
        bool metrics_collecting;
        bool health_monitoring;
        bool alerts_active;
        bool logging_active;
        std::chrono::steady_clock::time_point startup_time;
    };
    
    MonitoringStatus get_status() const;
    
    void export_dashboard_data(const std::string& output_file) const;
    void generate_health_report(const std::string& output_file) const;
    
    void configure_alert_thresholds();
    void setup_default_health_checks();

private:
    MonitoringManager() = default;
    
    std::atomic<bool> initialized_{false};
    std::chrono::steady_clock::time_point startup_time_;
    
    void setup_metric_based_alerts();
    void setup_health_based_alerts();
    void configure_logging();
};

#define LOG_TRACE(component, message, ...) \
    CipherProxy::Infrastructure::Logger::instance().trace(component, message, ##__VA_ARGS__)

#define LOG_DEBUG(component, message, ...) \
    CipherProxy::Infrastructure::Logger::instance().debug(component, message, ##__VA_ARGS__)

#define LOG_INFO(component, message, ...) \
    CipherProxy::Infrastructure::Logger::instance().info(component, message, ##__VA_ARGS__)

#define LOG_WARNING(component, message, ...) \
    CipherProxy::Infrastructure::Logger::instance().warning(component, message, ##__VA_ARGS__)

#define LOG_ERROR(component, message, ...) \
    CipherProxy::Infrastructure::Logger::instance().error(component, message, ##__VA_ARGS__)

#define LOG_CRITICAL(component, message, ...) \
    CipherProxy::Infrastructure::Logger::instance().critical(component, message, ##__VA_ARGS__)

}
