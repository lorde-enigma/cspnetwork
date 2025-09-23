#pragma once

#include <string>
#include <array>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <functional>

namespace seeded_vpn::domain {

using IPv6Address = std::array<uint8_t, 16>;
using SeedValue = uint64_t;
using ClientId = std::string;
using ConnectionId = uint64_t;

struct ConnectionParameters {
    IPv6Address server_address;
    uint16_t server_port{1194};
    std::string protocol{"udp"};
    std::string encryption_key;
    std::chrono::seconds timeout{30};
};

enum class SeedStrategy {
    PER_CONNECTION,
    PER_CLIENT, 
    PER_TIME_WINDOW,
    HYBRID
};

enum class ConnectionState {
    CONNECTING,
    AUTHENTICATING,
    CONNECTED,
    DISCONNECTING,
    DISCONNECTED,
    ERROR,
    ACTIVE,
    SUSPENDED,
    FAILED,
    TERMINATED
};

enum class LogLevel : uint8_t {
    TRACE,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

struct ConnectionContext {
    ConnectionId connection_id{};
    ClientId client_id{};
    IPv6Address assigned_address{};
    ConnectionState state{ConnectionState::DISCONNECTED};
    std::chrono::steady_clock::time_point created_at{};
    std::chrono::steady_clock::time_point last_activity{};
};

struct SeedContext {
    ClientId client_id;
    ConnectionId connection_id;
};

struct Seed {
    SeedValue value;
    std::string algorithm{"sha256"};
    std::chrono::steady_clock::time_point generated_at;
};

struct SeedData {
    Seed value;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    bool is_active{false};
};

inline std::ostream& operator<<(std::ostream& os, const IPv6Address& addr) {
    os << std::hex << std::setfill('0');
    for (size_t i = 0; i < addr.size(); i += 2) {
        if (i > 0) os << ":";
        os << std::setw(2) << static_cast<int>(addr[i])
           << std::setw(2) << static_cast<int>(addr[i + 1]);
    }
    return os << std::dec;
}

}

namespace std {
    template<>
    struct hash<seeded_vpn::domain::IPv6Address> {
        size_t operator()(const seeded_vpn::domain::IPv6Address& addr) const noexcept {
            size_t result = 0;
            for (size_t i = 0; i < addr.size(); ++i) {
                result ^= hash<uint8_t>{}(addr[i]) + 0x9e3779b9 + (result << 6) + (result >> 2);
            }
            return result;
        }
    };
}
