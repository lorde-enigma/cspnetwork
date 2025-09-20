#pragma once

#include "domain/types.h"
#include <array>
#include <vector>
#include <cstdint>
#include <chrono>
#include <functional>
#include <unordered_map>
#include <cstring>
#include <optional>

namespace seeded_vpn::infrastructure {

enum class VPNPacketType : uint8_t {
    HANDSHAKE_INIT = 0x01,
    HANDSHAKE_RESPONSE = 0x02,
    HANDSHAKE_COMPLETE = 0x03,
    DATA_PACKET = 0x10,
    KEEPALIVE = 0x20,
    DISCONNECT = 0x30,
    ERROR_RESPONSE = 0xFF
};

enum class CompressionType : uint8_t {
    NONE = 0x00,
    LZ4 = 0x01,
    ZSTD = 0x02
};

struct VPNPacketHeader {
    uint8_t version;
    VPNPacketType type;
    CompressionType compression;
    uint8_t flags;
    uint32_t sequence_number;
    uint32_t payload_length;
    uint64_t timestamp;
    std::array<uint8_t, 16> checksum;
    
    static constexpr size_t HEADER_SIZE = 32;
    
    std::vector<uint8_t> serialize() const;
    static VPNPacketHeader deserialize(const std::vector<uint8_t>& data);
    bool is_valid() const;
};

class VPNPacket {
public:
    VPNPacket(VPNPacketType type, std::vector<uint8_t> payload = {});
    
    void set_sequence_number(uint32_t seq);
    void set_compression(CompressionType compression);
    void set_flags(uint8_t flags);
    void set_payload(std::vector<uint8_t> payload);
    
    VPNPacketType get_type() const;
    uint32_t get_sequence_number() const;
    const std::vector<uint8_t>& get_payload() const;
    size_t get_total_size() const;
    
    std::vector<uint8_t> serialize() const;
    static VPNPacket deserialize(const std::vector<uint8_t>& data);
    
    bool verify_checksum() const;
    void update_checksum();

private:
    VPNPacketHeader header_;
    std::vector<uint8_t> payload_;
    
    std::array<uint8_t, 16> calculate_checksum() const;
};

enum class VPNConnectionState : uint8_t {
    DISCONNECTED = 0,
    CONNECTING = 1,
    AUTHENTICATING = 2,
    CONNECTED = 3,
    DISCONNECTING = 4,
    ERROR_STATE = 5
};

class VPNStateMachine {
public:
    VPNStateMachine();
    
    void process_packet(const VPNPacket& packet);
    void initiate_handshake();
    void handle_timeout();
    void disconnect();
    
    VPNConnectionState get_state() const;
    bool is_connected() const;
    bool can_send_data() const;
    
    void set_state_change_callback(std::function<void(VPNConnectionState, VPNConnectionState)> callback);

private:
    VPNConnectionState current_state_;
    std::chrono::steady_clock::time_point last_activity_;
    std::function<void(VPNConnectionState, VPNConnectionState)> state_change_callback_;
    uint32_t handshake_timeout_ms_;
    uint32_t keepalive_interval_ms_;
    
    void transition_to(VPNConnectionState new_state);
    void handle_handshake_init(const VPNPacket& packet);
    void handle_handshake_response(const VPNPacket& packet);
    void handle_handshake_complete(const VPNPacket& packet);
    void handle_data_packet(const VPNPacket& packet);
    void handle_keepalive(const VPNPacket& packet);
    void handle_disconnect(const VPNPacket& packet);
    void handle_error_response(const VPNPacket& packet);
    
    bool is_timeout_expired() const;
    void update_activity();
};

class VPNProtocolHandler {
public:
    VPNProtocolHandler();
    
    void initialize(const std::string& config_path);
    void initialize(const domain::ConnectionParameters& params);
    
    std::vector<uint8_t> encapsulate_ipv6_packet(const std::vector<uint8_t>& ipv6_packet);
    std::vector<uint8_t> decapsulate_vpn_packet(const std::vector<uint8_t>& vpn_packet);
    
    VPNPacket create_handshake_init(const std::string& client_id);
    VPNPacket create_handshake_response(uint64_t challenge);
    VPNPacket create_handshake_complete();
    VPNPacket create_data_packet(const std::vector<uint8_t>& data);
    VPNPacket create_keepalive();
    VPNPacket create_disconnect(const std::string& reason = "");
    VPNPacket create_error_response(const std::string& error);
    
    void process_incoming_packet(const std::vector<uint8_t>& raw_data);
    std::vector<std::vector<uint8_t>> get_outgoing_packets();
    
    void set_packet_handler(std::function<void(const VPNPacket&)> handler);
    void set_error_handler(std::function<void(const std::string&)> handler);

private:
    VPNStateMachine state_machine_;
    uint32_t next_sequence_number_;
    std::vector<std::vector<uint8_t>> outgoing_queue_;
    std::function<void(const VPNPacket&)> packet_handler_;
    std::function<void(const std::string&)> error_handler_;
    
    bool validate_packet_structure(const std::vector<uint8_t>& data);
    void queue_outgoing_packet(const VPNPacket& packet);
    uint32_t get_next_sequence_number();
};

class VPNFragmentationHandler {
public:
    VPNFragmentationHandler(size_t max_fragment_size = 1400);
    
    std::vector<VPNPacket> fragment_packet(const VPNPacket& packet);
    std::optional<VPNPacket> reassemble_fragments(const VPNPacket& fragment);
    
    void cleanup_expired_fragments();
    size_t get_pending_fragments_count() const;

private:
    size_t max_fragment_size_;
    std::unordered_map<uint32_t, std::vector<VPNPacket>> fragment_buffers_;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> fragment_timestamps_;
    std::chrono::seconds fragment_timeout_;
    
    bool is_fragmented_packet(const VPNPacket& packet);
    uint32_t get_fragment_id(const VPNPacket& packet);
    bool all_fragments_received(uint32_t fragment_id) const;
};

}
