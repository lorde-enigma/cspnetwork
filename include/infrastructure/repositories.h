#pragma once

#include "../domain/interfaces.h"
#include "../domain/types.h"
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <shared_mutex>
#include <fstream>
#include <thread>
#include <atomic>
#include <random>

namespace seeded_vpn::infrastructure {

class InMemoryConnectionRepository : public domain::IConnectionRepository {
private:
    std::unordered_map<domain::ConnectionId, domain::ConnectionContext> connections_;
    std::unordered_map<domain::ClientId, std::vector<domain::ConnectionId>> client_connections_;
    mutable std::shared_mutex repository_mutex_;

public:
    void store(const domain::ConnectionContext& connection) override;
    std::optional<domain::ConnectionContext> find_by_id(domain::ConnectionId id) override;
    std::vector<domain::ConnectionContext> find_by_client(const domain::ClientId& client_id) override;
    void remove(domain::ConnectionId id) override;
    void update_state(domain::ConnectionId id, domain::ConnectionState state) override;
    std::vector<domain::ConnectionContext> get_all_active() override;
    
private:
    void update_client_index(const domain::ConnectionContext& connection);
    void remove_from_client_index(domain::ConnectionId id, const domain::ClientId& client_id);
};

class FileSystemLogger : public domain::ILogger {
private:
    std::ofstream log_file_;
    mutable std::mutex log_mutex_;
    std::string log_file_path_;
    domain::LogLevel current_level_;
    bool console_output_enabled_;

public:
    explicit FileSystemLogger(const std::string& log_file_path, domain::LogLevel level = domain::LogLevel::INFO);
    ~FileSystemLogger();
    
    void trace(const std::string& message) override;
    void debug(const std::string& message) override;
    void info(const std::string& message) override;
    void warn(const std::string& message) override;
    void error(const std::string& message) override;
    void fatal(const std::string& message) override;
    void set_level(domain::LogLevel level) override;
    
    void enable_console_output(bool enable);
    void rotate_log_file();
    
private:
    void write_log(domain::LogLevel level, const std::string& message);
    std::string format_log_entry(domain::LogLevel level, const std::string& message);
    std::string level_to_string(domain::LogLevel level);
    std::string get_timestamp();
};

class YamlConfigurationProvider : public domain::IConfigurationProvider {
private:
    std::string config_file_path_;
    std::unordered_map<std::string, std::string> config_data_;
    mutable std::shared_mutex config_mutex_;
    std::atomic<bool> auto_reload_enabled_;
    std::thread config_watcher_thread_;
    std::atomic<bool> watcher_running_;

public:
    explicit YamlConfigurationProvider(const std::string& config_file_path);
    ~YamlConfigurationProvider();
    
    std::string get_string(const std::string& key, const std::string& default_value = "") const override;
    int get_int(const std::string& key, int default_value = 0) const override;
    bool get_bool(const std::string& key, bool default_value = false) const override;
    std::vector<std::string> get_string_list(const std::string& key) const override;
    void reload() override;
    
    void enable_auto_reload(bool enable);
    bool validate_config_file();
    
private:
    void load_config_file();
    void watch_config_file();
    std::string parse_value(const std::string& raw_value) const;
    bool parse_bool_value(const std::string& value) const;
    std::vector<std::string> parse_list_value(const std::string& value) const;
};

class ConcreteSeedGenerator : public domain::ISeedGenerator {
private:
    domain::SeedStrategy current_strategy_;
    domain::SeedValue base_seed_;
    std::unordered_map<domain::ClientId, domain::SeedValue> client_seed_cache_;
    std::chrono::steady_clock::time_point last_rotation_;
    mutable std::mutex generator_mutex_;
    std::mt19937_64 random_generator_;

public:
    explicit ConcreteSeedGenerator(domain::SeedStrategy strategy = domain::SeedStrategy::PER_CLIENT);
    
    domain::SeedValue generate(const domain::SeedContext& context) override;
    void set_strategy(domain::SeedStrategy strategy) override;
    void rotate_base_seed() override;
    bool validate_seed(domain::SeedValue seed) const override;
    
private:
    domain::SeedValue generate_per_connection(const domain::SeedContext& context);
    domain::SeedValue generate_per_client(const domain::SeedContext& context);
    domain::SeedValue generate_per_time_window(const domain::SeedContext& context);
    domain::SeedValue generate_hybrid(const domain::SeedContext& context);
    
    domain::SeedValue hash_string(const std::string& input) const;
    domain::SeedValue combine_seeds(domain::SeedValue seed1, domain::SeedValue seed2) const;
    void initialize_random_generator();
};

class MemoryPoolIPv6Manager : public domain::IIPv6AddressManager {
private:
    std::vector<domain::IPv6Address> address_pool_;
    std::unordered_map<domain::SeedValue, domain::IPv6Address> seed_to_address_;
    std::unordered_set<domain::IPv6Address> allocated_addresses_;
    domain::IPv6Address base_prefix_;
    uint8_t prefix_length_;
    size_t pool_size_;
    mutable std::shared_mutex manager_mutex_;

public:
    MemoryPoolIPv6Manager(const domain::IPv6Address& base_prefix, uint8_t prefix_length, size_t initial_pool_size = 10000);
    
    domain::IPv6Address allocate(domain::SeedValue seed) override;
    void release(const domain::IPv6Address& address) override;
    bool is_available(const domain::IPv6Address& address) override;
    std::vector<domain::IPv6Address> get_active_addresses() override;
    bool expand_pool() override;
    size_t get_pool_size() const override;
    
private:
    void initialize_address_pool();
    domain::IPv6Address seed_to_ipv6_address(domain::SeedValue seed) const;
    bool is_valid_ipv6_address(const domain::IPv6Address& address) const;
    bool is_in_prefix_range(const domain::IPv6Address& address) const;
    void generate_additional_addresses(size_t count);
};

class LinuxNetworkInterface : public domain::INetworkInterface {
private:
    std::string interface_name_;
    int netlink_socket_;
    bool interface_created_;
    std::vector<domain::IPv6Address> configured_addresses_;
    mutable std::mutex interface_mutex_;

public:
    explicit LinuxNetworkInterface(const std::string& interface_name = "cspnetwork0");
    ~LinuxNetworkInterface();
    
    void add_address(const domain::IPv6Address& address) override;
    void remove_address(const domain::IPv6Address& address) override;
    void add_route(const domain::IPv6Address& dest, const domain::IPv6Address& gateway) override;
    void remove_route(const domain::IPv6Address& dest) override;
    bool is_interface_up() const override;
    void bring_up() override;
    void bring_down() override;
    
private:
    void create_interface();
    void destroy_interface();
    bool execute_ip_command(const std::string& command) const;
    std::string ipv6_to_string(const domain::IPv6Address& address) const;
    int setup_netlink_socket();
    void cleanup_netlink_socket();
};

class OpenSSLCryptographyService : public domain::ICryptographyService {
private:
    bool openssl_initialized_;

public:
    OpenSSLCryptographyService();
    ~OpenSSLCryptographyService();
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) override;
    std::vector<uint8_t> generate_key() override;
    bool verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key) override;
    
private:
    void initialize_openssl();
    void cleanup_openssl();
    std::vector<uint8_t> chacha20_poly1305_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key);
    std::vector<uint8_t> chacha20_poly1305_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key);
    std::vector<uint8_t> generate_secure_random(size_t length);
};

}
