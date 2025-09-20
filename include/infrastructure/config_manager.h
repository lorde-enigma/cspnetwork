#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <functional>
#include <shared_mutex>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <variant>
#include <filesystem>
#include <thread>
#include <condition_variable>

namespace CipherProxy::Infrastructure {

class ConfigManager {
public:
    using ConfigValue = std::variant<std::string, int, double, bool, std::vector<std::string>>;
    using ConfigChangeCallback = std::function<void(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value)>;
    
    struct ServerConfig {
        struct Network {
            std::string listen_address = "::";
            int listen_port = 5555;
            std::string interface_name = "tun0";
            int mtu = 1420;
            bool ipv6_only = true;
        } network;
        
        struct IPv6Pool {
            std::string prefix = "2001:db8:vpn::/48";
            size_t subnet_size = 64;
            size_t pool_size = 1000000;
            bool enable_auto_expansion = true;
            double expansion_threshold = 0.8;
            size_t expansion_increment = 100000;
        } ipv6_pool;
        
        struct Security {
            std::string cipher = "chacha20-poly1305";
            std::string cert_file = "/etc/vpn/server.crt";
            std::string key_file = "/etc/vpn/server.key";
            std::string ca_file = "/etc/vpn/ca.crt";
            std::chrono::seconds key_rotation_interval{3600};
            bool enable_perfect_forward_secrecy = true;
            int max_handshake_attempts = 3;
            std::chrono::seconds handshake_timeout{30};
        } security;
        
        struct SeedManagement {
            std::string strategy = "ADAPTIVE";
            std::chrono::seconds rotation_interval{300};
            size_t pool_size = 10000;
            bool enable_geographic_distribution = true;
            double load_balancing_threshold = 0.7;
        } seed_management;
        
        struct Performance {
            size_t thread_pool_size = 0; // 0 = auto detect
            size_t connection_pool_size = 1000;
            size_t packet_buffer_size = 65536;
            bool enable_numa_awareness = true;
            size_t memory_pool_size_mb = 256;
            bool enable_cpu_affinity = true;
        } performance;
        
        struct Monitoring {
            bool enable_metrics = true;
            bool enable_health_monitoring = true;
            bool enable_alerts = true;
            std::string log_directory = "/var/log/cspnetwork";
            std::string log_level = "INFO";
            bool enable_structured_logging = true;
            std::chrono::hours log_rotation_interval{24};
            size_t max_log_size_mb = 100;
        } monitoring;
        
        struct Routing {
            bool enable_load_balancing = true;
            std::string load_balancing_algorithm = "ROUND_ROBIN";
            bool enable_failover = true;
            std::chrono::seconds health_check_interval{30};
            int max_connection_failures = 3;
            bool enable_traffic_shaping = false;
            double bandwidth_limit_mbps = 0.0; // 0 = unlimited
        } routing;
    };
    
    enum class ConfigFormat {
        YAML,
        JSON,
        INI
    };
    
    enum class ValidationResult {
        VALID,
        INVALID_FORMAT,
        MISSING_REQUIRED_FIELD,
        INVALID_VALUE_TYPE,
        INVALID_VALUE_RANGE,
        UNKNOWN_FIELD
    };
    
    struct ValidationError {
        ValidationResult result;
        std::string field;
        std::string message;
        std::string suggestion;
    };
    
    static ConfigManager& instance();
    
    void initialize(const std::string& config_file_path = "", bool auto_reload = true);
    void shutdown();
    
    bool load_config(const std::string& file_path, ConfigFormat format = ConfigFormat::YAML);
    bool load_from_string(const std::string& config_data, ConfigFormat format = ConfigFormat::YAML);
    bool save_config(const std::string& file_path = "", ConfigFormat format = ConfigFormat::YAML);
    
    std::vector<ValidationError> validate_config(const ServerConfig& config) const;
    bool is_config_valid() const;
    
    const ServerConfig& get_server_config() const;
    void update_server_config(const ServerConfig& config);
    
    template<typename T>
    T get_value(const std::string& key, const T& default_value = T{}) const;
    
    template<typename T>
    bool set_value(const std::string& key, const T& value);
    
    bool has_key(const std::string& key) const;
    void remove_key(const std::string& key);
    
    void load_environment_variables(const std::string& prefix = "VPN_");
    void apply_command_line_args(int argc, char* argv[]);
    
    void register_change_callback(const std::string& key, ConfigChangeCallback callback);
    void unregister_change_callback(const std::string& key);
    
    void enable_auto_reload(bool enable = true);
    void reload_config();
    bool is_auto_reload_enabled() const;
    
    std::string export_config_json() const;
    std::string export_config_yaml() const;
    
    void create_default_config_file(const std::string& file_path) const;
    
    std::unordered_map<std::string, ConfigValue> get_all_values() const;
    std::vector<std::string> get_config_keys() const;
    
    std::filesystem::file_time_type get_last_modified() const;
    std::string get_config_file_path() const;
    ConfigFormat get_config_format() const;
    
    void set_read_only(bool read_only = true);
    bool is_read_only() const;
    
    std::string get_config_checksum() const;
    
private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    mutable std::shared_mutex config_mutex_;
    ServerConfig server_config_;
    std::unordered_map<std::string, ConfigValue> config_values_;
    std::unordered_map<std::string, ConfigChangeCallback> change_callbacks_;
    
    std::string config_file_path_;
    ConfigFormat config_format_ = ConfigFormat::YAML;
    std::filesystem::file_time_type last_modified_;
    std::atomic<bool> auto_reload_enabled_{false};
    std::atomic<bool> read_only_{false};
    std::atomic<bool> initialized_{false};
    
    std::thread file_watcher_thread_;
    std::atomic<bool> watching_{false};
    
    void file_watcher_loop();
    void notify_config_change(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value);
    
    bool parse_yaml_config(const std::string& content);
    bool parse_json_config(const std::string& content);
    bool parse_ini_config(const std::string& content);
    
    std::string serialize_yaml_config() const;
    std::string serialize_json_config() const;
    std::string serialize_ini_config() const;
    
    ConfigFormat detect_format(const std::string& file_path) const;
    
    void populate_server_config_from_map();
    void populate_map_from_server_config();
    
    std::string compute_checksum() const;
    
    ValidationError validate_network_config(const ServerConfig::Network& config) const;
    ValidationError validate_ipv6_pool_config(const ServerConfig::IPv6Pool& config) const;
    ValidationError validate_security_config(const ServerConfig::Security& config) const;
    ValidationError validate_seed_management_config(const ServerConfig::SeedManagement& config) const;
    ValidationError validate_performance_config(const ServerConfig::Performance& config) const;
    ValidationError validate_monitoring_config(const ServerConfig::Monitoring& config) const;
    ValidationError validate_routing_config(const ServerConfig::Routing& config) const;
    
    bool is_valid_ipv6_prefix(const std::string& prefix) const;
    bool is_valid_file_path(const std::string& path) const;
    bool is_valid_directory_path(const std::string& path) const;
    bool file_exists(const std::string& path) const;
    
    void set_default_values();
    void merge_environment_variables(const std::string& prefix);
    void merge_command_line_args(const std::unordered_map<std::string, std::string>& args);
    
    template<typename T>
    void safe_set_config_value(const std::string& key, const T& value);
    
    template<typename T>
    std::optional<T> safe_get_config_value(const std::string& key) const;
};

template<typename T>
T ConfigManager::get_value(const std::string& key, const T& default_value) const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        try {
            return std::get<T>(it->second);
        } catch (const std::bad_variant_access&) {
            return default_value;
        }
    }
    
    return default_value;
}

template<typename T>
bool ConfigManager::set_value(const std::string& key, const T& value) {
    if (read_only_.load()) {
        return false;
    }
    
    std::unique_lock<std::shared_mutex> lock(config_mutex_);
    
    ConfigValue old_value;
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        old_value = it->second;
    }
    
    config_values_[key] = ConfigValue(value);
    
    lock.unlock();
    notify_config_change(key, old_value, ConfigValue(value));
    
    return true;
}

template<typename T>
void ConfigManager::safe_set_config_value(const std::string& key, const T& value) {
    config_values_[key] = ConfigValue(value);
}

template<typename T>
std::optional<T> ConfigManager::safe_get_config_value(const std::string& key) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        try {
            return std::get<T>(it->second);
        } catch (const std::bad_variant_access&) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

}
