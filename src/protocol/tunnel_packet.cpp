#include "../../include/infrastructure/tunnel_packet.h"
#include "../../include/infrastructure/crc32.h"
#include <cstring>
#include <stdexcept>

using namespace seeded_vpn::protocol;

TunnelPacket::TunnelPacket(PacketType type, uint32_t session_id, std::vector<uint8_t> payload)
    : type_(type), session_id_(session_id), payload_(std::move(payload)) {
    calculate_crc();
}

std::unique_ptr<TunnelPacket> TunnelPacket::parse(const uint8_t* data, size_t size) {
    if (size < 13) {
        return nullptr;
    }
    
    PacketType type = static_cast<PacketType>(data[0]);
    uint32_t session_id = *reinterpret_cast<const uint32_t*>(data + 1);
    uint32_t payload_size = *reinterpret_cast<const uint32_t*>(data + 5);
    uint32_t received_crc = *reinterpret_cast<const uint32_t*>(data + 9);
    
    if (size < 13 + payload_size) {
        return nullptr;
    }
    
    std::vector<uint8_t> payload(data + 13, data + 13 + payload_size);
    auto packet = std::unique_ptr<TunnelPacket>(new TunnelPacket(type, session_id, std::move(payload)));
    
    if (!packet->verify_crc(data, size)) {
        return nullptr;
    }
    
    return packet;
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_auth_request(const std::string& credentials) {
    std::vector<uint8_t> payload(credentials.begin(), credentials.end());
    return std::unique_ptr<TunnelPacket>(new TunnelPacket(PacketType::AUTH_REQUEST, 0, std::move(payload)));
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_auth_response(AuthResult result, const std::string& allocated_ip) {
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>(result));
    payload.insert(payload.end(), allocated_ip.begin(), allocated_ip.end());
    return std::unique_ptr<TunnelPacket>(new TunnelPacket(PacketType::AUTH_RESPONSE, 0, std::move(payload)));
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_data_packet(uint32_t session_id, const std::vector<uint8_t>& payload) {
    return std::unique_ptr<TunnelPacket>(new TunnelPacket(PacketType::DATA, session_id, payload));
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_keepalive(uint32_t session_id) {
    return std::unique_ptr<TunnelPacket>(new TunnelPacket(PacketType::KEEPALIVE, session_id, {}));
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_disconnect(uint32_t session_id) {
    return std::unique_ptr<TunnelPacket>(new TunnelPacket(PacketType::DISCONNECT, session_id, {}));
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_error_response(const std::string& error_message) {
    std::vector<uint8_t> payload(error_message.begin(), error_message.end());
    return std::unique_ptr<TunnelPacket>(new TunnelPacket(PacketType::ERROR_RESPONSE, 0, std::move(payload)));
}

void TunnelPacket::get_data_payload(uint8_t* buffer) const {
    if (!payload_.empty() && buffer) {
        std::memcpy(buffer, payload_.data(), payload_.size());
    }
}

std::vector<uint8_t> TunnelPacket::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(13 + payload_.size());
    
    data.push_back(static_cast<uint8_t>(type_));
    
    auto session_bytes = reinterpret_cast<const uint8_t*>(&session_id_);
    data.insert(data.end(), session_bytes, session_bytes + 4);
    
    uint32_t payload_size = static_cast<uint32_t>(payload_.size());
    auto size_bytes = reinterpret_cast<const uint8_t*>(&payload_size);
    data.insert(data.end(), size_bytes, size_bytes + 4);
    
    auto crc_bytes = reinterpret_cast<const uint8_t*>(&crc32_);
    data.insert(data.end(), crc_bytes, crc_bytes + 4);
    
    data.insert(data.end(), payload_.begin(), payload_.end());
    
    return data;
}

void TunnelPacket::calculate_crc() {
    std::vector<uint8_t> data_for_crc;
    data_for_crc.push_back(static_cast<uint8_t>(type_));
    
    auto session_bytes = reinterpret_cast<const uint8_t*>(&session_id_);
    data_for_crc.insert(data_for_crc.end(), session_bytes, session_bytes + 4);
    
    uint32_t payload_size = static_cast<uint32_t>(payload_.size());
    auto size_bytes = reinterpret_cast<const uint8_t*>(&payload_size);
    data_for_crc.insert(data_for_crc.end(), size_bytes, size_bytes + 4);
    
    data_for_crc.insert(data_for_crc.end(), payload_.begin(), payload_.end());
    
    crc32_ = seeded_vpn::infrastructure::CRC32::calculate(data_for_crc.data(), data_for_crc.size());
}

bool TunnelPacket::verify_crc(const uint8_t* data, size_t size) const {
    if (size < 13) {
        return false;
    }
    
    uint32_t payload_size = *reinterpret_cast<const uint32_t*>(data + 5);
    uint32_t received_crc = *reinterpret_cast<const uint32_t*>(data + 9);
    
    std::vector<uint8_t> data_for_crc;
    data_for_crc.insert(data_for_crc.end(), data, data + 9);
    data_for_crc.insert(data_for_crc.end(), data + 13, data + 13 + payload_size);
    
    uint32_t calculated_crc = seeded_vpn::infrastructure::CRC32::calculate(data_for_crc.data(), data_for_crc.size());
    
    return calculated_crc == received_crc;
}
