#include "infrastructure/config_manager.h"
#include "infrastructure/monitoring_system.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <yaml-cpp/yaml.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <arpa/inet.h>

namespace CipherProxy::Infrastructure {

ConfigManager& ConfigManager::instance() {
    static ConfigManager instance;
    return instance;
}

void ConfigManager::initialize(const std::string& config_file_path, bool auto_reload) {
    if (initialized_.exchange(true)) {
        return;
    }
    
    config_file_path_ = config_file_path;
    set_default_values();
    
    if (!config_file_path_.empty()) {
        if (std::filesystem::exists(config_file_path_)) {
            config_format_ = detect_format(config_file_path_);
            if (!load_config(config_file_path_, config_format_)) {
                LOG_WARNING("config", "failed to load config file, using defaults", 
                           {{"file", config_file_path_}});
            }
        } else {
            LOG_INFO("config", "config file not found, creating default", 
                    {{"file", config_file_path_}});
            create_default_config_file(config_file_path_);
        }
    }
    
    load_environment_variables();
    
    if (auto_reload && !config_file_path_.empty()) {
        enable_auto_reload(true);
    }
    
    populate_server_config_from_map();
    
    auto validation_errors = validate_config(server_config_);
    if (!validation_errors.empty()) {
        LOG_WARNING("config", "configuration validation warnings found");
        for (const auto& error : validation_errors) {
            LOG_WARNING("config", "validation error: " + error.message, 
                       {{"field", error.field}, {"suggestion", error.suggestion}});
        }
    }
    
    LOG_INFO("config", "configuration manager initialized");
}

void ConfigManager::shutdown() {
    if (!initialized_.exchange(false)) {
        return;
    }
    
    enable_auto_reload(false);
    LOG_INFO("config", "configuration manager shutdown");
}

bool ConfigManager::load_config(const std::string& file_path, ConfigFormat format) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        LOG_ERROR("config", "failed to open config file", {{"file", file_path}});
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    file.close();
    
    if (content.empty()) {
        LOG_WARNING("config", "config file is empty", {{"file", file_path}});
        return false;
    }
    
    bool success = load_from_string(content, format);
    if (success) {
        config_file_path_ = file_path;
        config_format_ = format;
        last_modified_ = std::filesystem::last_write_time(file_path);
        LOG_INFO("config", "config loaded successfully", {{"file", file_path}});
    }
    
    return success;
}

bool ConfigManager::load_from_string(const std::string& config_data, ConfigFormat format) {
    std::unique_lock<std::shared_mutex> lock(config_mutex_);
    
    try {
        switch (format) {
            case ConfigFormat::YAML:
                return parse_yaml_config(config_data);
            case ConfigFormat::JSON:
                return parse_json_config(config_data);
            case ConfigFormat::INI:
                return parse_ini_config(config_data);
            default:
                LOG_ERROR("config", "unsupported config format");
                return false;
        }
    } catch (const std::exception& e) {
        LOG_ERROR("config", "failed to parse config", {{"error", e.what()}});
        return false;
    }
}

bool ConfigManager::save_config(const std::string& file_path, ConfigFormat format) {
    if (read_only_.load()) {
        LOG_WARNING("config", "cannot save config in read-only mode");
        return false;
    }
    
    std::string target_file = file_path.empty() ? config_file_path_ : file_path;
    ConfigFormat target_format = file_path.empty() ? config_format_ : format;
    
    if (target_file.empty()) {
        LOG_ERROR("config", "no target file specified for config save");
        return false;
    }
    
    std::string content;
    {
        std::shared_lock<std::shared_mutex> lock(config_mutex_);
        populate_map_from_server_config();
        
        switch (target_format) {
            case ConfigFormat::YAML:
                content = serialize_yaml_config();
                break;
            case ConfigFormat::JSON:
                content = serialize_json_config();
                break;
            case ConfigFormat::INI:
                content = serialize_ini_config();
                break;
            default:
                LOG_ERROR("config", "unsupported config format for save");
                return false;
        }
    }
    
    std::ofstream file(target_file);
    if (!file.is_open()) {
        LOG_ERROR("config", "failed to open file for writing", {{"file", target_file}});
        return false;
    }
    
    file << content;
    file.close();
    
    LOG_INFO("config", "config saved successfully", {{"file", target_file}});
    return true;
}

std::vector<ConfigManager::ValidationError> ConfigManager::validate_config(const ServerConfig& config) const {
    std::vector<ValidationError> errors;
    
    auto network_error = validate_network_config(config.network);
    if (network_error.result != ValidationResult::VALID) {
        errors.push_back(network_error);
    }
    
    auto ipv6_error = validate_ipv6_pool_config(config.ipv6_pool);
    if (ipv6_error.result != ValidationResult::VALID) {
        errors.push_back(ipv6_error);
    }
    
    auto security_error = validate_security_config(config.security);
    if (security_error.result != ValidationResult::VALID) {
        errors.push_back(security_error);
    }
    
    auto seed_error = validate_seed_management_config(config.seed_management);
    if (seed_error.result != ValidationResult::VALID) {
        errors.push_back(seed_error);
    }
    
    auto performance_error = validate_performance_config(config.performance);
    if (performance_error.result != ValidationResult::VALID) {
        errors.push_back(performance_error);
    }
    
    auto monitoring_error = validate_monitoring_config(config.monitoring);
    if (monitoring_error.result != ValidationResult::VALID) {
        errors.push_back(monitoring_error);
    }
    
    auto routing_error = validate_routing_config(config.routing);
    if (routing_error.result != ValidationResult::VALID) {
        errors.push_back(routing_error);
    }
    
    return errors;
}

bool ConfigManager::is_config_valid() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    auto errors = validate_config(server_config_);
    return errors.empty();
}

const ConfigManager::ServerConfig& ConfigManager::get_server_config() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return server_config_;
}

void ConfigManager::update_server_config(const ServerConfig& config) {
    if (read_only_.load()) {
        LOG_WARNING("config", "cannot update config in read-only mode");
        return;
    }
    
    auto validation_errors = validate_config(config);
    if (!validation_errors.empty()) {
        LOG_ERROR("config", "config validation failed, update rejected");
        for (const auto& error : validation_errors) {
            LOG_ERROR("config", "validation error: " + error.message, 
                     {{"field", error.field}});
        }
        return;
    }
    
    {
        std::unique_lock<std::shared_mutex> lock(config_mutex_);
        ServerConfig old_config = server_config_;
        server_config_ = config;
        populate_map_from_server_config();
    }
    
    LOG_INFO("config", "server configuration updated");
}

bool ConfigManager::has_key(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return config_values_.find(key) != config_values_.end();
}

void ConfigManager::remove_key(const std::string& key) {
    if (read_only_.load()) {
        return;
    }
    
    std::unique_lock<std::shared_mutex> lock(config_mutex_);
    config_values_.erase(key);
}

void ConfigManager::load_environment_variables(const std::string& prefix) {
    merge_environment_variables(prefix);
    LOG_INFO("config", "environment variables loaded", {{"prefix", prefix}});
}

void ConfigManager::apply_command_line_args(int argc, char* argv[]) {
    std::unordered_map<std::string, std::string> args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.starts_with("--")) {
            auto eq_pos = arg.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = arg.substr(2, eq_pos - 2);
                std::string value = arg.substr(eq_pos + 1);
                args[key] = value;
            } else if (i + 1 < argc) {
                std::string key = arg.substr(2);
                std::string value = argv[++i];
                args[key] = value;
            }
        }
    }
    
    merge_command_line_args(args);
    LOG_INFO("config", "command line arguments applied", {{"count", std::to_string(args.size())}});
}

void ConfigManager::register_change_callback(const std::string& key, ConfigChangeCallback callback) {
    std::unique_lock<std::shared_mutex> lock(config_mutex_);
    change_callbacks_[key] = callback;
}

void ConfigManager::unregister_change_callback(const std::string& key) {
    std::unique_lock<std::shared_mutex> lock(config_mutex_);
    change_callbacks_.erase(key);
}

void ConfigManager::enable_auto_reload(bool enable) {
    if (enable == auto_reload_enabled_.load()) {
        return;
    }
    
    auto_reload_enabled_ = enable;
    
    if (enable && !config_file_path_.empty()) {
        watching_ = true;
        file_watcher_thread_ = std::thread(&ConfigManager::file_watcher_loop, this);
        LOG_INFO("config", "auto-reload enabled");
    } else {
        watching_ = false;
        if (file_watcher_thread_.joinable()) {
            file_watcher_thread_.join();
        }
        LOG_INFO("config", "auto-reload disabled");
    }
}

void ConfigManager::reload_config() {
    if (config_file_path_.empty()) {
        LOG_WARNING("config", "no config file to reload");
        return;
    }
    
    if (!std::filesystem::exists(config_file_path_)) {
        LOG_WARNING("config", "config file no longer exists", {{"file", config_file_path_}});
        return;
    }
    
    auto current_modified = std::filesystem::last_write_time(config_file_path_);
    if (current_modified == last_modified_) {
        return;
    }
    
    LOG_INFO("config", "reloading configuration", {{"file", config_file_path_}});
    
    if (load_config(config_file_path_, config_format_)) {
        populate_server_config_from_map();
        LOG_INFO("config", "configuration reloaded successfully");
    } else {
        LOG_ERROR("config", "failed to reload configuration");
    }
}

bool ConfigManager::is_auto_reload_enabled() const {
    return auto_reload_enabled_.load();
}

std::string ConfigManager::export_config_json() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return serialize_json_config();
}

std::string ConfigManager::export_config_yaml() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return serialize_yaml_config();
}

void ConfigManager::create_default_config_file(const std::string& file_path) const {
    ServerConfig default_config;
    
    std::string content;
    ConfigFormat format = detect_format(file_path);
    
    switch (format) {
        case ConfigFormat::YAML:
            content = serialize_yaml_config();
            break;
        case ConfigFormat::JSON:
            content = serialize_json_config();
            break;
        default:
            content = serialize_yaml_config();
            break;
    }
    
    std::filesystem::create_directories(std::filesystem::path(file_path).parent_path());
    
    std::ofstream file(file_path);
    if (file.is_open()) {
        file << content;
        file.close();
        LOG_INFO("config", "default config file created", {{"file", file_path}});
    } else {
        LOG_ERROR("config", "failed to create default config file", {{"file", file_path}});
    }
}

std::unordered_map<std::string, ConfigManager::ConfigValue> ConfigManager::get_all_values() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return config_values_;
}

std::vector<std::string> ConfigManager::get_config_keys() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    std::vector<std::string> keys;
    for (const auto& [key, value] : config_values_) {
        keys.push_back(key);
    }
    return keys;
}

std::filesystem::file_time_type ConfigManager::get_last_modified() const {
    return last_modified_;
}

std::string ConfigManager::get_config_file_path() const {
    return config_file_path_;
}

ConfigManager::ConfigFormat ConfigManager::get_config_format() const {
    return config_format_;
}

void ConfigManager::set_read_only(bool read_only) {
    read_only_ = read_only;
    LOG_INFO("config", "read-only mode " + std::string(read_only ? "enabled" : "disabled"));
}

bool ConfigManager::is_read_only() const {
    return read_only_.load();
}

std::string ConfigManager::get_config_checksum() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return compute_checksum();
}

void ConfigManager::file_watcher_loop() {
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        LOG_ERROR("config", "failed to initialize inotify");
        return;
    }
    
    int watch_fd = inotify_add_watch(inotify_fd, config_file_path_.c_str(), IN_MODIFY | IN_MOVE_SELF);
    if (watch_fd < 0) {
        LOG_ERROR("config", "failed to add inotify watch", {{"file", config_file_path_}});
        close(inotify_fd);
        return;
    }
    
    char buffer[4096];
    while (watching_.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(inotify_fd, &fds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int select_result = select(inotify_fd + 1, &fds, nullptr, nullptr, &timeout);
        if (select_result > 0 && FD_ISSET(inotify_fd, &fds)) {
            ssize_t length = read(inotify_fd, buffer, sizeof(buffer));
            if (length > 0) {
                reload_config();
            }
        }
    }
    
    inotify_rm_watch(inotify_fd, watch_fd);
    close(inotify_fd);
}

void ConfigManager::notify_config_change(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value) {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    auto it = change_callbacks_.find(key);
    if (it != change_callbacks_.end()) {
        try {
            it->second(key, old_value, new_value);
        } catch (const std::exception& e) {
            LOG_ERROR("config", "config change callback failed", 
                     {{"key", key}, {"error", e.what()}});
        }
    }
}

bool ConfigManager::parse_yaml_config(const std::string& content) {
    try {
        YAML::Node root = YAML::Load(content);
        
        if (root["network"]) {
            auto network = root["network"];
            if (network["listen_address"]) server_config_.network.listen_address = network["listen_address"].as<std::string>();
            if (network["listen_port"]) server_config_.network.listen_port = network["listen_port"].as<int>();
            if (network["interface_name"]) server_config_.network.interface_name = network["interface_name"].as<std::string>();
            if (network["mtu"]) server_config_.network.mtu = network["mtu"].as<int>();
            if (network["ipv6_only"]) server_config_.network.ipv6_only = network["ipv6_only"].as<bool>();
        }
        
        if (root["ipv6_pool"]) {
            auto pool = root["ipv6_pool"];
            if (pool["prefix"]) server_config_.ipv6_pool.prefix = pool["prefix"].as<std::string>();
            if (pool["subnet_size"]) server_config_.ipv6_pool.subnet_size = pool["subnet_size"].as<size_t>();
            if (pool["pool_size"]) server_config_.ipv6_pool.pool_size = pool["pool_size"].as<size_t>();
            if (pool["enable_auto_expansion"]) server_config_.ipv6_pool.enable_auto_expansion = pool["enable_auto_expansion"].as<bool>();
        }
        
        if (root["security"]) {
            auto security = root["security"];
            if (security["cipher"]) server_config_.security.cipher = security["cipher"].as<std::string>();
            if (security["cert_file"]) server_config_.security.cert_file = security["cert_file"].as<std::string>();
            if (security["key_file"]) server_config_.security.key_file = security["key_file"].as<std::string>();
            if (security["ca_file"]) server_config_.security.ca_file = security["ca_file"].as<std::string>();
        }
        
        return true;
    } catch (const YAML::Exception& e) {
        LOG_ERROR("config", "yaml parsing failed", {{"error", e.what()}});
        return false;
    }
}

bool ConfigManager::parse_json_config(const std::string& content) {
    try {
        auto json = nlohmann::json::parse(content);
        
        if (json.contains("network")) {
            auto network = json["network"];
            if (network.contains("listen_address")) server_config_.network.listen_address = network["listen_address"];
            if (network.contains("listen_port")) server_config_.network.listen_port = network["listen_port"];
            if (network.contains("interface_name")) server_config_.network.interface_name = network["interface_name"];
            if (network.contains("mtu")) server_config_.network.mtu = network["mtu"];
            if (network.contains("ipv6_only")) server_config_.network.ipv6_only = network["ipv6_only"];
        }
        
        if (json.contains("ipv6_pool")) {
            auto pool = json["ipv6_pool"];
            if (pool.contains("prefix")) server_config_.ipv6_pool.prefix = pool["prefix"];
            if (pool.contains("subnet_size")) server_config_.ipv6_pool.subnet_size = pool["subnet_size"];
            if (pool.contains("pool_size")) server_config_.ipv6_pool.pool_size = pool["pool_size"];
        }
        
        return true;
    } catch (const nlohmann::json::exception& e) {
        LOG_ERROR("config", "json parsing failed", {{"error", e.what()}});
        return false;
    }
}

bool ConfigManager::parse_ini_config(const std::string& content) {
    std::istringstream stream(content);
    std::string line;
    std::string current_section;
    
    while (std::getline(stream, line)) {
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }
        
        auto eq_pos = line.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = line.substr(0, eq_pos);
            std::string value = line.substr(eq_pos + 1);
            
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            if (!current_section.empty()) {
                key = current_section + "." + key;
            }
            
            config_values_[key] = ConfigValue(value);
        }
    }
    
    return true;
}

std::string ConfigManager::serialize_yaml_config() const {
    YAML::Node root;
    
    YAML::Node network;
    network["listen_address"] = server_config_.network.listen_address;
    network["listen_port"] = server_config_.network.listen_port;
    network["interface_name"] = server_config_.network.interface_name;
    network["mtu"] = server_config_.network.mtu;
    network["ipv6_only"] = server_config_.network.ipv6_only;
    root["network"] = network;
    
    YAML::Node ipv6_pool;
    ipv6_pool["prefix"] = server_config_.ipv6_pool.prefix;
    ipv6_pool["subnet_size"] = server_config_.ipv6_pool.subnet_size;
    ipv6_pool["pool_size"] = server_config_.ipv6_pool.pool_size;
    ipv6_pool["enable_auto_expansion"] = server_config_.ipv6_pool.enable_auto_expansion;
    root["ipv6_pool"] = ipv6_pool;
    
    YAML::Node security;
    security["cipher"] = server_config_.security.cipher;
    security["cert_file"] = server_config_.security.cert_file;
    security["key_file"] = server_config_.security.key_file;
    security["ca_file"] = server_config_.security.ca_file;
    root["security"] = security;
    
    std::ostringstream out;
    out << root;
    return out.str();
}

std::string ConfigManager::serialize_json_config() const {
    nlohmann::json root;
    
    root["network"]["listen_address"] = server_config_.network.listen_address;
    root["network"]["listen_port"] = server_config_.network.listen_port;
    root["network"]["interface_name"] = server_config_.network.interface_name;
    root["network"]["mtu"] = server_config_.network.mtu;
    root["network"]["ipv6_only"] = server_config_.network.ipv6_only;
    
    root["ipv6_pool"]["prefix"] = server_config_.ipv6_pool.prefix;
    root["ipv6_pool"]["subnet_size"] = server_config_.ipv6_pool.subnet_size;
    root["ipv6_pool"]["pool_size"] = server_config_.ipv6_pool.pool_size;
    root["ipv6_pool"]["enable_auto_expansion"] = server_config_.ipv6_pool.enable_auto_expansion;
    
    root["security"]["cipher"] = server_config_.security.cipher;
    root["security"]["cert_file"] = server_config_.security.cert_file;
    root["security"]["key_file"] = server_config_.security.key_file;
    root["security"]["ca_file"] = server_config_.security.ca_file;
    
    return root.dump(2);
}

std::string ConfigManager::serialize_ini_config() const {
    std::ostringstream ini;
    
    ini << "[network]\n";
    ini << "listen_address = " << server_config_.network.listen_address << "\n";
    ini << "listen_port = " << server_config_.network.listen_port << "\n";
    ini << "interface_name = " << server_config_.network.interface_name << "\n";
    ini << "mtu = " << server_config_.network.mtu << "\n";
    ini << "ipv6_only = " << (server_config_.network.ipv6_only ? "true" : "false") << "\n\n";
    
    ini << "[ipv6_pool]\n";
    ini << "prefix = " << server_config_.ipv6_pool.prefix << "\n";
    ini << "subnet_size = " << server_config_.ipv6_pool.subnet_size << "\n";
    ini << "pool_size = " << server_config_.ipv6_pool.pool_size << "\n";
    ini << "enable_auto_expansion = " << (server_config_.ipv6_pool.enable_auto_expansion ? "true" : "false") << "\n\n";
    
    ini << "[security]\n";
    ini << "cipher = " << server_config_.security.cipher << "\n";
    ini << "cert_file = " << server_config_.security.cert_file << "\n";
    ini << "key_file = " << server_config_.security.key_file << "\n";
    ini << "ca_file = " << server_config_.security.ca_file << "\n";
    
    return ini.str();
}

ConfigManager::ConfigFormat ConfigManager::detect_format(const std::string& file_path) const {
    std::string extension = std::filesystem::path(file_path).extension();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    if (extension == ".yaml" || extension == ".yml") {
        return ConfigFormat::YAML;
    } else if (extension == ".json") {
        return ConfigFormat::JSON;
    } else if (extension == ".ini" || extension == ".conf") {
        return ConfigFormat::INI;
    }
    
    return ConfigFormat::YAML;
}

void ConfigManager::populate_server_config_from_map() {
    // This would populate the server_config_ from config_values_ map
    // Implementation depends on the specific mapping strategy
}

void ConfigManager::populate_map_from_server_config() {
    // This would populate the config_values_ map from server_config_
    // Implementation depends on the specific mapping strategy
}

std::string ConfigManager::compute_checksum() const {
    std::string config_string = serialize_json_config();
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, config_string.c_str(), config_string.size());
    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return oss.str();
}

ConfigManager::ValidationError ConfigManager::validate_network_config(const ServerConfig::Network& config) const {
    if (config.listen_port <= 0 || config.listen_port > 65535) {
        return {ValidationResult::INVALID_VALUE_RANGE, "network.listen_port", 
                "port must be between 1 and 65535", "use a valid port number"};
    }
    
    if (config.mtu < 576 || config.mtu > 9000) {
        return {ValidationResult::INVALID_VALUE_RANGE, "network.mtu",
                "mtu must be between 576 and 9000", "use standard mtu values like 1420"};
    }
    
    return {ValidationResult::VALID, "", "", ""};
}

ConfigManager::ValidationError ConfigManager::validate_ipv6_pool_config(const ServerConfig::IPv6Pool& config) const {
    if (!is_valid_ipv6_prefix(config.prefix)) {
        return {ValidationResult::INVALID_VALUE_TYPE, "ipv6_pool.prefix",
                "invalid ipv6 prefix format", "use format like 2001:db8::/48"};
    }
    
    if (config.pool_size == 0) {
        return {ValidationResult::INVALID_VALUE_RANGE, "ipv6_pool.pool_size",
                "pool size cannot be zero", "use a positive number"};
    }
    
    return {ValidationResult::VALID, "", "", ""};
}

ConfigManager::ValidationError ConfigManager::validate_security_config(const ServerConfig::Security& config) const {
    if (!file_exists(config.cert_file)) {
        return {ValidationResult::MISSING_REQUIRED_FIELD, "security.cert_file",
                "certificate file not found", "ensure certificate file exists"};
    }
    
    if (!file_exists(config.key_file)) {
        return {ValidationResult::MISSING_REQUIRED_FIELD, "security.key_file",
                "private key file not found", "ensure private key file exists"};
    }
    
    return {ValidationResult::VALID, "", "", ""};
}

ConfigManager::ValidationError ConfigManager::validate_seed_management_config(const ServerConfig::SeedManagement& config) const {
    std::vector<std::string> valid_strategies = {"PER_CONNECTION", "PER_CLIENT", "PER_TIME_WINDOW", 
                                                "HYBRID", "GEOGRAPHIC_BASED", "LOAD_BALANCED", "ADAPTIVE"};
    
    if (std::find(valid_strategies.begin(), valid_strategies.end(), config.strategy) == valid_strategies.end()) {
        return {ValidationResult::INVALID_VALUE_TYPE, "seed_management.strategy",
                "invalid seed strategy", "use one of: PER_CONNECTION, PER_CLIENT, ADAPTIVE, etc."};
    }
    
    return {ValidationResult::VALID, "", "", ""};
}

ConfigManager::ValidationError ConfigManager::validate_performance_config(const ServerConfig::Performance& config) const {
    if (config.memory_pool_size_mb > 8192) {
        return {ValidationResult::INVALID_VALUE_RANGE, "performance.memory_pool_size_mb",
                "memory pool size too large", "consider using less than 8GB"};
    }
    
    return {ValidationResult::VALID, "", "", ""};
}

ConfigManager::ValidationError ConfigManager::validate_monitoring_config(const ServerConfig::Monitoring& config) const {
    if (!is_valid_directory_path(config.log_directory)) {
        return {ValidationResult::INVALID_VALUE_TYPE, "monitoring.log_directory",
                "invalid log directory path", "ensure directory exists or can be created"};
    }
    
    std::vector<std::string> valid_levels = {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};
    if (std::find(valid_levels.begin(), valid_levels.end(), config.log_level) == valid_levels.end()) {
        return {ValidationResult::INVALID_VALUE_TYPE, "monitoring.log_level",
                "invalid log level", "use one of: TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL"};
    }
    
    return {ValidationResult::VALID, "", "", ""};
}

ConfigManager::ValidationError ConfigManager::validate_routing_config(const ServerConfig::Routing& config) const {
    std::vector<std::string> valid_algorithms = {"ROUND_ROBIN", "LEAST_CONNECTIONS", "WEIGHTED_ROUND_ROBIN", "HASH_BASED"};
    
    if (std::find(valid_algorithms.begin(), valid_algorithms.end(), config.load_balancing_algorithm) == valid_algorithms.end()) {
        return {ValidationResult::INVALID_VALUE_TYPE, "routing.load_balancing_algorithm",
                "invalid load balancing algorithm", "use one of: ROUND_ROBIN, LEAST_CONNECTIONS, etc."};
    }
    
    return {ValidationResult::VALID, "", "", ""};
}

bool ConfigManager::is_valid_ipv6_prefix(const std::string& prefix) const {
    std::regex ipv6_regex(R"(^([0-9a-fA-F:]+)\/([0-9]{1,3})$)");
    return std::regex_match(prefix, ipv6_regex);
}

bool ConfigManager::is_valid_file_path(const std::string& path) const {
    return !path.empty() && path.find('\0') == std::string::npos;
}

bool ConfigManager::is_valid_directory_path(const std::string& path) const {
    return is_valid_file_path(path);
}

bool ConfigManager::file_exists(const std::string& path) const {
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

void ConfigManager::set_default_values() {
    server_config_ = ServerConfig{};
}

void ConfigManager::merge_environment_variables(const std::string& prefix) {
    for (char** env = environ; *env != nullptr; ++env) {
        std::string env_var = *env;
        if (env_var.starts_with(prefix)) {
            auto eq_pos = env_var.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = env_var.substr(prefix.length(), eq_pos - prefix.length());
                std::string value = env_var.substr(eq_pos + 1);
                
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                std::replace(key.begin(), key.end(), '_', '.');
                
                config_values_[key] = ConfigValue(value);
            }
        }
    }
}

void ConfigManager::merge_command_line_args(const std::unordered_map<std::string, std::string>& args) {
    for (const auto& [key, value] : args) {
        config_values_[key] = ConfigValue(value);
    }
}

}
