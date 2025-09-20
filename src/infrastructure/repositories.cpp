#include "../../include/infrastructure/repositories.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include <algorithm>
#include <random>
#include <fstream>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <cstring>
#include <linux/rtnetlink.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace seeded_vpn::infrastructure {

void InMemoryConnectionRepository::store(const domain::ConnectionContext& connection) {
    std::unique_lock lock(repository_mutex_);
    connections_[connection.connection_id] = connection;
    update_client_index(connection);
}

std::optional<domain::ConnectionContext> InMemoryConnectionRepository::find_by_id(domain::ConnectionId id) {
    std::shared_lock lock(repository_mutex_);
    auto it = connections_.find(id);
    return it != connections_.end() ? std::make_optional(it->second) : std::nullopt;
}

std::vector<domain::ConnectionContext> InMemoryConnectionRepository::find_by_client(const domain::ClientId& client_id) {
    std::shared_lock lock(repository_mutex_);
    std::vector<domain::ConnectionContext> result;
    
    auto client_it = client_connections_.find(client_id);
    if (client_it != client_connections_.end()) {
        for (const auto& conn_id : client_it->second) {
            auto conn_it = connections_.find(conn_id);
            if (conn_it != connections_.end()) {
                result.push_back(conn_it->second);
            }
        }
    }
    return result;
}

void InMemoryConnectionRepository::remove(domain::ConnectionId id) {
    std::unique_lock lock(repository_mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
        remove_from_client_index(id, it->second.client_id);
        connections_.erase(it);
    }
}

void InMemoryConnectionRepository::update_state(domain::ConnectionId id, domain::ConnectionState state) {
    std::unique_lock lock(repository_mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
        it->second.state = state;
        it->second.last_activity = std::chrono::steady_clock::now();
    }
}

std::vector<domain::ConnectionContext> InMemoryConnectionRepository::get_all_active() {
    std::shared_lock lock(repository_mutex_);
    std::vector<domain::ConnectionContext> active_connections;
    
    for (const auto& [id, connection] : connections_) {
        if (connection.state == domain::ConnectionState::ACTIVE) {
            active_connections.push_back(connection);
        }
    }
    return active_connections;
}

void InMemoryConnectionRepository::update_client_index(const domain::ConnectionContext& connection) {
    client_connections_[connection.client_id].push_back(connection.connection_id);
}

void InMemoryConnectionRepository::remove_from_client_index(domain::ConnectionId id, const domain::ClientId& client_id) {
    auto client_it = client_connections_.find(client_id);
    if (client_it != client_connections_.end()) {
        auto& connections = client_it->second;
        connections.erase(std::remove(connections.begin(), connections.end(), id), connections.end());
        if (connections.empty()) {
            client_connections_.erase(client_it);
        }
    }
}

FileSystemLogger::FileSystemLogger(const std::string& log_file_path, domain::LogLevel level)
    : log_file_path_(log_file_path), current_level_(level), console_output_enabled_(false) {
    log_file_.open(log_file_path_, std::ios::out | std::ios::app);
    if (!log_file_.is_open()) {
        throw std::runtime_error("failed to open log file: " + log_file_path_);
    }
}

FileSystemLogger::~FileSystemLogger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void FileSystemLogger::trace(const std::string& message) {
    if (current_level_ <= domain::LogLevel::TRACE) {
        write_log(domain::LogLevel::TRACE, message);
    }
}

void FileSystemLogger::debug(const std::string& message) {
    if (current_level_ <= domain::LogLevel::TRACE) {
        write_log(domain::LogLevel::TRACE, message);
    }
}

void FileSystemLogger::info(const std::string& message) {
    if (current_level_ <= domain::LogLevel::INFO) {
        write_log(domain::LogLevel::INFO, message);
    }
}

void FileSystemLogger::warn(const std::string& message) {
    if (current_level_ <= domain::LogLevel::WARNING) {
        write_log(domain::LogLevel::WARNING, message);
    }
}

void FileSystemLogger::error(const std::string& message) {
    if (current_level_ <= domain::LogLevel::ERROR) {
        write_log(domain::LogLevel::ERROR, message);
    }
}

void FileSystemLogger::fatal(const std::string& message) {
    write_log(domain::LogLevel::CRITICAL, message);
}

void FileSystemLogger::set_level(domain::LogLevel level) {
    std::lock_guard lock(log_mutex_);
    current_level_ = level;
}

void FileSystemLogger::write_log(domain::LogLevel level, const std::string& message) {
    std::lock_guard lock(log_mutex_);
    std::string formatted_entry = format_log_entry(level, message);
    
    if (log_file_.is_open()) {
        log_file_ << formatted_entry << std::endl;
        log_file_.flush();
    }
    
    if (console_output_enabled_) {
        std::cout << formatted_entry << std::endl;
    }
}

std::string FileSystemLogger::format_log_entry(domain::LogLevel level, const std::string& message) {
    std::ostringstream oss;
    oss << "[" << get_timestamp() << "] "
        << "[" << level_to_string(level) << "] "
        << message;
    return oss.str();
}

std::string FileSystemLogger::level_to_string(domain::LogLevel level) {
    switch (level) {
        case domain::LogLevel::TRACE: return "trace";
        case domain::LogLevel::INFO: return "info";
        case domain::LogLevel::WARNING: return "warning";
        case domain::LogLevel::ERROR: return "error";
        case domain::LogLevel::CRITICAL: return "critical";
        default: return "unknown";
    }
}

std::string FileSystemLogger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return oss.str();
}

YamlConfigurationProvider::YamlConfigurationProvider(const std::string& config_file_path)
    : config_file_path_(config_file_path), auto_reload_enabled_(false), watcher_running_(false) {
    load_config_file();
}

YamlConfigurationProvider::~YamlConfigurationProvider() {
    if (watcher_running_) {
        watcher_running_ = false;
        if (config_watcher_thread_.joinable()) {
            config_watcher_thread_.join();
        }
    }
}

std::string YamlConfigurationProvider::get_string(const std::string& key, const std::string& default_value) const {
    std::shared_lock lock(config_mutex_);
    auto it = config_data_.find(key);
    return it != config_data_.end() ? it->second : default_value;
}

int YamlConfigurationProvider::get_int(const std::string& key, int default_value) const {
    std::string value = get_string(key);
    if (value.empty()) return default_value;
    
    try {
        return std::stoi(value);
    } catch (const std::exception&) {
        return default_value;
    }
}

bool YamlConfigurationProvider::get_bool(const std::string& key, bool default_value) const {
    std::string value = get_string(key);
    if (value.empty()) return default_value;
    return parse_bool_value(value);
}

std::vector<std::string> YamlConfigurationProvider::get_string_list(const std::string& key) const {
    std::string value = get_string(key);
    if (value.empty()) return {};
    return parse_list_value(value);
}

void YamlConfigurationProvider::reload() {
    load_config_file();
}

void YamlConfigurationProvider::load_config_file() {
    std::unique_lock lock(config_mutex_);
    config_data_.clear();
    
    std::ifstream file(config_file_path_);
    if (!file.is_open()) {
        throw std::runtime_error("failed to open config file: " + config_file_path_);
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            config_data_[key] = parse_value(value);
        }
    }
}

std::string YamlConfigurationProvider::parse_value(const std::string& raw_value) const {
    std::string value = raw_value;
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    }
    return value;
}

bool YamlConfigurationProvider::parse_bool_value(const std::string& value) const {
    std::string lower_value = value;
    std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);
    return lower_value == "true" || lower_value == "yes" || lower_value == "1" || lower_value == "on";
}

std::vector<std::string> YamlConfigurationProvider::parse_list_value(const std::string& value) const {
    std::vector<std::string> result;
    std::stringstream ss(value);
    std::string item;
    
    while (std::getline(ss, item, ',')) {
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) {
            result.push_back(parse_value(item));
        }
    }
    return result;
}

ConcreteSeedGenerator::ConcreteSeedGenerator(domain::SeedStrategy strategy)
    : current_strategy_(strategy), base_seed_(0), last_rotation_(std::chrono::steady_clock::now()) {
    initialize_random_generator();
    rotate_base_seed();
}

domain::SeedValue ConcreteSeedGenerator::generate(const domain::SeedContext& context) {
    std::lock_guard lock(generator_mutex_);
    
    switch (current_strategy_) {
        case domain::SeedStrategy::PER_CONNECTION:
            return generate_per_connection(context);
        case domain::SeedStrategy::PER_CLIENT:
            return generate_per_client(context);
        case domain::SeedStrategy::PER_TIME_WINDOW:
            return generate_per_time_window(context);
        case domain::SeedStrategy::HYBRID:
            return generate_hybrid(context);
        default:
            return generate_per_client(context);
    }
}

void ConcreteSeedGenerator::set_strategy(domain::SeedStrategy strategy) {
    std::lock_guard lock(generator_mutex_);
    current_strategy_ = strategy;
}

void ConcreteSeedGenerator::rotate_base_seed() {
    std::lock_guard lock(generator_mutex_);
    base_seed_ = random_generator_();
    last_rotation_ = std::chrono::steady_clock::now();
}

bool ConcreteSeedGenerator::validate_seed(domain::SeedValue seed) const {
    return seed != 0;
}

domain::SeedValue ConcreteSeedGenerator::generate_per_connection(const domain::SeedContext& context) {
    return combine_seeds(base_seed_, hash_string(context.client_id + std::to_string(context.connection_id)));
}

domain::SeedValue ConcreteSeedGenerator::generate_per_client(const domain::SeedContext& context) {
    auto it = client_seed_cache_.find(context.client_id);
    if (it != client_seed_cache_.end()) {
        return it->second;
    }
    
    domain::SeedValue client_seed = combine_seeds(base_seed_, hash_string(context.client_id));
    client_seed_cache_[context.client_id] = client_seed;
    return client_seed;
}

domain::SeedValue ConcreteSeedGenerator::generate_per_time_window(const domain::SeedContext& context) {
    auto now = std::chrono::steady_clock::now();
    auto window = std::chrono::duration_cast<std::chrono::hours>(now.time_since_epoch()).count();
    return combine_seeds(base_seed_, hash_string(context.client_id + std::to_string(window)));
}

domain::SeedValue ConcreteSeedGenerator::generate_hybrid(const domain::SeedContext& context) {
    domain::SeedValue client_seed = generate_per_client(context);
    domain::SeedValue time_seed = generate_per_time_window(context);
    return combine_seeds(client_seed, time_seed);
}

domain::SeedValue ConcreteSeedGenerator::hash_string(const std::string& input) const {
    std::hash<std::string> hasher;
    return static_cast<domain::SeedValue>(hasher(input));
}

domain::SeedValue ConcreteSeedGenerator::combine_seeds(domain::SeedValue seed1, domain::SeedValue seed2) const {
    return seed1 ^ (seed2 << 1);
}

void ConcreteSeedGenerator::initialize_random_generator() {
    std::random_device rd;
    random_generator_.seed(rd());
}

MemoryPoolIPv6Manager::MemoryPoolIPv6Manager(const domain::IPv6Address& base_prefix, uint8_t prefix_length, size_t initial_pool_size)
    : base_prefix_(base_prefix), prefix_length_(prefix_length), pool_size_(initial_pool_size) {
    initialize_address_pool();
}

domain::IPv6Address MemoryPoolIPv6Manager::allocate(domain::SeedValue seed) {
    std::unique_lock lock(manager_mutex_);
    
    auto it = seed_to_address_.find(seed);
    if (it != seed_to_address_.end()) {
        return it->second;
    }
    
    domain::IPv6Address address = seed_to_ipv6_address(seed);
    if (allocated_addresses_.count(address) == 0) {
        allocated_addresses_.insert(address);
        seed_to_address_[seed] = address;
        return address;
    }
    
    for (const auto& pool_address : address_pool_) {
        if (allocated_addresses_.count(pool_address) == 0) {
            allocated_addresses_.insert(pool_address);
            seed_to_address_[seed] = pool_address;
            return pool_address;
        }
    }
    
    throw std::runtime_error("no available ipv6 addresses in pool");
}

void MemoryPoolIPv6Manager::release(const domain::IPv6Address& address) {
    std::unique_lock lock(manager_mutex_);
    allocated_addresses_.erase(address);
    
    auto it = std::find_if(seed_to_address_.begin(), seed_to_address_.end(),
        [&address](const auto& pair) { return pair.second == address; });
    if (it != seed_to_address_.end()) {
        seed_to_address_.erase(it);
    }
}

bool MemoryPoolIPv6Manager::is_available(const domain::IPv6Address& address) {
    std::shared_lock lock(manager_mutex_);
    return allocated_addresses_.count(address) == 0;
}

std::vector<domain::IPv6Address> MemoryPoolIPv6Manager::get_active_addresses() {
    std::shared_lock lock(manager_mutex_);
    return {allocated_addresses_.begin(), allocated_addresses_.end()};
}

bool MemoryPoolIPv6Manager::expand_pool() {
    std::unique_lock lock(manager_mutex_);
    size_t additional_addresses = pool_size_ / 2;
    generate_additional_addresses(additional_addresses);
    pool_size_ += additional_addresses;
    return true;
}

size_t MemoryPoolIPv6Manager::get_pool_size() const {
    std::shared_lock lock(manager_mutex_);
    return pool_size_;
}

void MemoryPoolIPv6Manager::initialize_address_pool() {
    generate_additional_addresses(pool_size_);
}

domain::IPv6Address MemoryPoolIPv6Manager::seed_to_ipv6_address(domain::SeedValue seed) const {
    domain::IPv6Address address = base_prefix_;
    
    uint64_t seed_low = seed & 0xFFFFFFFFFFFFFFFF;
    uint64_t seed_high = (seed >> 32) & 0xFFFFFFFF;
    
    uint32_t seed_high_be = htonl(seed_high);
    uint32_t seed_low_be = htonl(seed_low);
    
    std::memcpy(&address[8], &seed_high_be, 4);
    std::memcpy(&address[12], &seed_low_be, 4);
    
    return address;
}

void MemoryPoolIPv6Manager::generate_additional_addresses(size_t count) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    
    for (size_t i = 0; i < count; ++i) {
        domain::SeedValue random_seed = gen();
        domain::IPv6Address address = seed_to_ipv6_address(random_seed);
        
        if (is_valid_ipv6_address(address) && is_in_prefix_range(address)) {
            address_pool_.push_back(address);
        }
    }
}

bool MemoryPoolIPv6Manager::is_valid_ipv6_address(const domain::IPv6Address& address) const {
    return true;
}

bool MemoryPoolIPv6Manager::is_in_prefix_range(const domain::IPv6Address& address) const {
    uint8_t prefix_bytes = prefix_length_ / 8;
    uint8_t prefix_bits = prefix_length_ % 8;
    
    for (uint8_t i = 0; i < prefix_bytes; ++i) {
        if (address[i] != base_prefix_[i]) {
            return false;
        }
    }
    
    if (prefix_bits > 0) {
        uint8_t mask = 0xFF << (8 - prefix_bits);
        if ((address[prefix_bytes] & mask) != (base_prefix_[prefix_bytes] & mask)) {
            return false;
        }
    }
    
    return true;
}

LinuxNetworkInterface::LinuxNetworkInterface(const std::string& interface_name)
    : interface_name_(interface_name), netlink_socket_(-1), interface_created_(false) {
    netlink_socket_ = setup_netlink_socket();
    create_interface();
}

LinuxNetworkInterface::~LinuxNetworkInterface() {
    if (interface_created_) {
        destroy_interface();
    }
    cleanup_netlink_socket();
}

void LinuxNetworkInterface::add_address(const domain::IPv6Address& address) {
    std::lock_guard lock(interface_mutex_);
    std::string addr_str = ipv6_to_string(address);
    std::string command = "ip -6 addr add " + addr_str + "/128 dev " + interface_name_;
    
    if (execute_ip_command(command)) {
        configured_addresses_.push_back(address);
    }
}

void LinuxNetworkInterface::remove_address(const domain::IPv6Address& address) {
    std::lock_guard lock(interface_mutex_);
    std::string addr_str = ipv6_to_string(address);
    std::string command = "ip -6 addr del " + addr_str + "/128 dev " + interface_name_;
    
    if (execute_ip_command(command)) {
        configured_addresses_.erase(
            std::remove_if(configured_addresses_.begin(), configured_addresses_.end(),
                [&address](const domain::IPv6Address& addr) { 
                    return addr == address; 
                }),
            configured_addresses_.end());
    }
}

void LinuxNetworkInterface::add_route(const domain::IPv6Address& dest, const domain::IPv6Address& gateway) {
    std::lock_guard lock(interface_mutex_);
    std::string dest_str = ipv6_to_string(dest);
    std::string gateway_str = ipv6_to_string(gateway);
    std::string command = "ip -6 route add " + dest_str + " via " + gateway_str + " dev " + interface_name_;
    execute_ip_command(command);
}

void LinuxNetworkInterface::remove_route(const domain::IPv6Address& dest) {
    std::lock_guard lock(interface_mutex_);
    std::string dest_str = ipv6_to_string(dest);
    std::string command = "ip -6 route del " + dest_str + " dev " + interface_name_;
    execute_ip_command(command);
}

bool LinuxNetworkInterface::is_interface_up() const {
    std::string command = "ip link show " + interface_name_ + " up";
    return execute_ip_command(command);
}

void LinuxNetworkInterface::bring_up() {
    std::lock_guard lock(interface_mutex_);
    std::string command = "ip link set " + interface_name_ + " up";
    execute_ip_command(command);
}

void LinuxNetworkInterface::bring_down() {
    std::lock_guard lock(interface_mutex_);
    std::string command = "ip link set " + interface_name_ + " down";
    execute_ip_command(command);
}

void LinuxNetworkInterface::create_interface() {
    std::string command = "ip tuntap add " + interface_name_ + " mode tun";
    if (execute_ip_command(command)) {
        interface_created_ = true;
        bring_up();
    }
}

void LinuxNetworkInterface::destroy_interface() {
    std::string command = "ip tuntap del " + interface_name_ + " mode tun";
    execute_ip_command(command);
    interface_created_ = false;
}

bool LinuxNetworkInterface::execute_ip_command(const std::string& command) const {
    int result = system(command.c_str());
    return result == 0;
}

std::string LinuxNetworkInterface::ipv6_to_string(const domain::IPv6Address& address) const {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &address, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

int LinuxNetworkInterface::setup_netlink_socket() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        throw std::runtime_error("failed to create netlink socket");
    }
    return sock;
}

void LinuxNetworkInterface::cleanup_netlink_socket() {
    if (netlink_socket_ >= 0) {
        close(netlink_socket_);
        netlink_socket_ = -1;
    }
}

OpenSSLCryptographyService::OpenSSLCryptographyService() : openssl_initialized_(false) {
    initialize_openssl();
}

OpenSSLCryptographyService::~OpenSSLCryptographyService() {
    cleanup_openssl();
}

std::vector<uint8_t> OpenSSLCryptographyService::encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    return chacha20_poly1305_encrypt(data, key);
}

std::vector<uint8_t> OpenSSLCryptographyService::decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    return chacha20_poly1305_decrypt(data, key);
}

std::vector<uint8_t> OpenSSLCryptographyService::generate_key() {
    return generate_secure_random(32);
}

bool OpenSSLCryptographyService::verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key) {
    return false;
}

void OpenSSLCryptographyService::initialize_openssl() {
    if (!openssl_initialized_) {
        OpenSSL_add_all_algorithms();
        openssl_initialized_ = true;
    }
}

void OpenSSLCryptographyService::cleanup_openssl() {
    if (openssl_initialized_) {
        EVP_cleanup();
        openssl_initialized_ = false;
    }
}

std::vector<uint8_t> OpenSSLCryptographyService::chacha20_poly1305_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> nonce = generate_secure_random(12);
    std::vector<uint8_t> ciphertext(plaintext.size() + 16 + 12);
    
    std::copy(nonce.begin(), nonce.end(), ciphertext.begin());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("failed to create cipher context");
    
    try {
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1) {
            throw std::runtime_error("failed to initialize encryption");
        }
        
        int len;
        if (EVP_EncryptUpdate(ctx, ciphertext.data() + 12, &len, plaintext.data(), plaintext.size()) != 1) {
            throw std::runtime_error("failed to encrypt data");
        }
        
        int final_len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + 12 + len, &final_len) != 1) {
            throw std::runtime_error("failed to finalize encryption");
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ciphertext.data() + 12 + plaintext.size()) != 1) {
            throw std::runtime_error("failed to get authentication tag");
        }
        
        ciphertext.resize(12 + plaintext.size() + 16);
        
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<uint8_t> OpenSSLCryptographyService::chacha20_poly1305_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key) {
    if (ciphertext.size() < 28) {
        throw std::runtime_error("ciphertext too short");
    }
    
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + 12);
    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());
    std::vector<uint8_t> encrypted_data(ciphertext.begin() + 12, ciphertext.end() - 16);
    std::vector<uint8_t> plaintext(encrypted_data.size());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("failed to create cipher context");
    
    try {
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1) {
            throw std::runtime_error("failed to initialize decryption");
        }
        
        int len;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted_data.data(), encrypted_data.size()) != 1) {
            throw std::runtime_error("failed to decrypt data");
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data()) != 1) {
            throw std::runtime_error("failed to set authentication tag");
        }
        
        int final_len;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) {
            throw std::runtime_error("authentication failed");
        }
        
        plaintext.resize(len + final_len);
        
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::vector<uint8_t> OpenSSLCryptographyService::generate_secure_random(size_t length) {
    std::vector<uint8_t> random_data(length);
    if (RAND_bytes(random_data.data(), length) != 1) {
        throw std::runtime_error("failed to generate secure random data");
    }
    return random_data;
}

}
