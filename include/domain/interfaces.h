#pragma once

#include "types.h"
#include <memory>
#include <vector>
#include <future>
#include <optional>

namespace seeded_vpn::domain {

class ISeedGenerator {
public:
    virtual ~ISeedGenerator() = default;
    virtual SeedValue generate(const SeedContext& context) = 0;
    virtual void set_strategy(SeedStrategy strategy) = 0;
    virtual void rotate_base_seed() = 0;
    virtual bool validate_seed(SeedValue seed) const = 0;
};

class IIPv6AddressManager {
public:
    virtual ~IIPv6AddressManager() = default;
    virtual IPv6Address allocate(SeedValue seed) = 0;
    virtual void release(const IPv6Address& address) = 0;
    virtual bool is_available(const IPv6Address& address) = 0;
    virtual std::vector<IPv6Address> get_active_addresses() = 0;
    virtual bool expand_pool() = 0;
    virtual size_t get_pool_size() const = 0;
};

class IConnectionRepository {
public:
    virtual ~IConnectionRepository() = default;
    virtual void store(const ConnectionContext& connection) = 0;
    virtual std::optional<ConnectionContext> find_by_id(ConnectionId id) = 0;
    virtual std::vector<ConnectionContext> find_by_client(const ClientId& client_id) = 0;
    virtual void remove(ConnectionId id) = 0;
    virtual void update_state(ConnectionId id, ConnectionState state) = 0;
    virtual std::vector<ConnectionContext> get_all_active() = 0;
};

class INetworkInterface {
public:
    virtual ~INetworkInterface() = default;
    virtual void add_address(const IPv6Address& address) = 0;
    virtual void remove_address(const IPv6Address& address) = 0;
    virtual void add_route(const IPv6Address& dest, const IPv6Address& gateway) = 0;
    virtual void remove_route(const IPv6Address& dest) = 0;
    virtual bool is_interface_up() const = 0;
    virtual void bring_up() = 0;
    virtual void bring_down() = 0;
};

class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void trace(const std::string& message) = 0;
    virtual void debug(const std::string& message) = 0;
    virtual void info(const std::string& message) = 0;
    virtual void warn(const std::string& message) = 0;
    virtual void error(const std::string& message) = 0;
    virtual void fatal(const std::string& message) = 0;
    virtual void set_level(LogLevel level) = 0;
};

class IConfigurationProvider {
public:
    virtual ~IConfigurationProvider() = default;
    virtual std::string get_string(const std::string& key, const std::string& default_value = "") const = 0;
    virtual int get_int(const std::string& key, int default_value = 0) const = 0;
    virtual bool get_bool(const std::string& key, bool default_value = false) const = 0;
    virtual std::vector<std::string> get_string_list(const std::string& key) const = 0;
    virtual void reload() = 0;
};

class ICryptographyService {
public:
    virtual ~ICryptographyService() = default;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) = 0;
    virtual std::vector<uint8_t> generate_key() = 0;
    virtual bool verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key) = 0;
};

}
