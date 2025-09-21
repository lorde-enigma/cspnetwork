#include "protocol/udp_tunnel_protocol.h"
#include <cstring>

namespace seeded_vpn::protocol {

// AuthRequest implementation
AuthRequest AuthRequest::parse(const std::vector<uint8_t>& payload) {
    AuthRequest req;
    
    if (payload.size() < sizeof(uint64_t)) {
        return req;
    }
    
    size_t offset = 0;
    
    // Read timestamp
    std::memcpy(&req.timestamp, payload.data() + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    // Read client_id length and data
    if (offset + sizeof(uint16_t) > payload.size()) return req;
    uint16_t client_id_len;
    std::memcpy(&client_id_len, payload.data() + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    if (offset + client_id_len > payload.size()) return req;
    req.client_id.assign(payload.data() + offset, payload.data() + offset + client_id_len);
    offset += client_id_len;
    
    // Read auth_token length and data
    if (offset + sizeof(uint16_t) > payload.size()) return req;
    uint16_t token_len;
    std::memcpy(&token_len, payload.data() + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    if (offset + token_len > payload.size()) return req;
    req.auth_token.assign(payload.data() + offset, payload.data() + offset + token_len);
    
    return req;
}

std::vector<uint8_t> AuthRequest::serialize() const {
    std::vector<uint8_t> data;
    
    // Timestamp
    data.resize(sizeof(uint64_t));
    std::memcpy(data.data(), &timestamp, sizeof(uint64_t));
    
    // Client ID
    uint16_t client_id_len = client_id.size();
    size_t old_size = data.size();
    data.resize(old_size + sizeof(uint16_t) + client_id_len);
    std::memcpy(data.data() + old_size, &client_id_len, sizeof(uint16_t));
    std::memcpy(data.data() + old_size + sizeof(uint16_t), client_id.data(), client_id_len);
    
    // Auth token
    uint16_t token_len = auth_token.size();
    old_size = data.size();
    data.resize(old_size + sizeof(uint16_t) + token_len);
    std::memcpy(data.data() + old_size, &token_len, sizeof(uint16_t));
    std::memcpy(data.data() + old_size + sizeof(uint16_t), auth_token.data(), token_len);
    
    return data;
}

// AuthResponse implementation
AuthResponse AuthResponse::parse(const std::vector<uint8_t>& payload) {
    AuthResponse resp;
    
    if (payload.size() < sizeof(uint8_t)) {
        return resp;
    }
    
    size_t offset = 0;
    
    // Read result
    resp.result = static_cast<AuthResult>(payload[offset]);
    offset += sizeof(uint8_t);
    
    // Read allocated_ip length and data
    if (offset + sizeof(uint16_t) > payload.size()) return resp;
    uint16_t ip_len;
    std::memcpy(&ip_len, payload.data() + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    if (offset + ip_len > payload.size()) return resp;
    resp.allocated_ip.assign(payload.data() + offset, payload.data() + offset + ip_len);
    offset += ip_len;
    
    // Read server_config length and data
    if (offset + sizeof(uint16_t) > payload.size()) return resp;
    uint16_t config_len;
    std::memcpy(&config_len, payload.data() + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    if (offset + config_len > payload.size()) return resp;
    resp.server_config.assign(payload.data() + offset, payload.data() + offset + config_len);
    
    return resp;
}

std::vector<uint8_t> AuthResponse::serialize() const {
    std::vector<uint8_t> data;
    
    // Result
    data.push_back(static_cast<uint8_t>(result));
    
    // Allocated IP
    uint16_t ip_len = allocated_ip.size();
    size_t old_size = data.size();
    data.resize(old_size + sizeof(uint16_t) + ip_len);
    std::memcpy(data.data() + old_size, &ip_len, sizeof(uint16_t));
    std::memcpy(data.data() + old_size + sizeof(uint16_t), allocated_ip.data(), ip_len);
    
    // Server config
    uint16_t config_len = server_config.size();
    old_size = data.size();
    data.resize(old_size + sizeof(uint16_t) + config_len);
    std::memcpy(data.data() + old_size, &config_len, sizeof(uint16_t));
    std::memcpy(data.data() + old_size + sizeof(uint16_t), server_config.data(), config_len);
    
    return data;
}

}
