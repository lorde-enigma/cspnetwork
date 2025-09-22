#include "infrastructure/ip_pool.h"
#include <algorithm>
#include <sstream>
#include <random>
#include <arpa/inet.h>
#include <iostream>

namespace seeded_vpn::infrastructure {

IPRange::IPRange(const std::string& cidr) {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        throw std::invalid_argument("Invalid CIDR format");
    }
    
    network = cidr.substr(0, slash_pos);
    uint32_t prefix_len = std::stoul(cidr.substr(slash_pos + 1));
    
    uint32_t network_ip = IPPool::ip_string_to_numeric(network);
    uint32_t mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF;
    
    start_ip = network_ip & mask;
    end_ip = start_ip | (~mask & 0xFFFFFFFF);
    
    netmask = IPPool::ip_numeric_to_string(mask);
}

bool IPRange::contains(uint32_t ip) const {
    return ip >= start_ip && ip <= end_ip;
}

uint32_t IPRange::get_network_ip() const {
    return start_ip;
}

uint32_t IPRange::get_broadcast_ip() const {
    return end_ip;
}

size_t IPRange::get_available_count() const {
    return end_ip - start_ip - 1;
}

ClientIPAssignment::ClientIPAssignment(const std::string& id, uint32_t ip)
    : client_id(id), ip_numeric(ip), is_active(true) {
    ip_address = IPPool::ip_numeric_to_string(ip);
    assigned_at = std::chrono::system_clock::now();
    last_activity = assigned_at;
}

bool ClientIPAssignment::is_expired(std::chrono::seconds timeout) const {
    auto now = std::chrono::system_clock::now();
    return (now - last_activity) > timeout;
}

void ClientIPAssignment::update_activity() {
    last_activity = std::chrono::system_clock::now();
}

IPPool::IPPool(const std::string& cidr_range) {
    add_range(cidr_range);
}

IPPool::IPPool(const std::vector<std::string>& cidr_ranges) {
    for (const auto& cidr : cidr_ranges) {
        add_range(cidr);
    }
}

std::optional<std::string> IPPool::allocate_ip(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    auto existing = client_assignments_.find(client_id);
    if (existing != client_assignments_.end() && existing->second->is_active) {
        existing->second->update_activity();
        return existing->second->ip_address;
    }
    
    uint32_t ip = find_next_available_ip();
    if (ip == 0) {
        return std::nullopt;
    }
    
    auto assignment = std::make_unique<ClientIPAssignment>(client_id, ip);
    std::string ip_str = assignment->ip_address;
    
    allocated_ips_.insert(ip);
    ip_to_client_[ip] = client_id;
    client_assignments_[client_id] = std::move(assignment);
    
    return ip_str;
}

bool IPPool::release_ip(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    auto it = client_assignments_.find(client_id);
    if (it == client_assignments_.end()) {
        return false;
    }
    
    uint32_t ip = it->second->ip_numeric;
    allocated_ips_.erase(ip);
    ip_to_client_.erase(ip);
    client_assignments_.erase(it);
    
    return true;
}

bool IPPool::release_ip_by_address(const std::string& ip_address) {
    uint32_t ip = ip_string_to_numeric(ip_address);
    auto it = ip_to_client_.find(ip);
    if (it != ip_to_client_.end()) {
        return release_ip(it->second);
    }
    return false;
}

bool IPPool::is_allocated(const std::string& ip_address) const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    uint32_t ip = ip_string_to_numeric(ip_address);
    return allocated_ips_.count(ip) > 0;
}

std::optional<std::string> IPPool::get_client_ip(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    auto it = client_assignments_.find(client_id);
    if (it != client_assignments_.end() && it->second->is_active) {
        return it->second->ip_address;
    }
    return std::nullopt;
}

std::optional<std::string> IPPool::get_ip_client(const std::string& ip_address) const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    uint32_t ip = ip_string_to_numeric(ip_address);
    auto it = ip_to_client_.find(ip);
    if (it != ip_to_client_.end()) {
        return it->second;
    }
    return std::nullopt;
}

size_t IPPool::get_total_ips() const {
    size_t total = 0;
    for (const auto& range : ip_ranges_) {
        total += range->get_available_count();
    }
    return total;
}

size_t IPPool::get_allocated_count() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return allocated_ips_.size();
}

size_t IPPool::get_available_count() const {
    return get_total_ips() - get_allocated_count();
}

double IPPool::get_utilization_percentage() const {
    size_t total = get_total_ips();
    if (total == 0) return 0.0;
    return (static_cast<double>(get_allocated_count()) / total) * 100.0;
}

bool IPPool::update_client_activity(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    auto it = client_assignments_.find(client_id);
    if (it != client_assignments_.end()) {
        it->second->update_activity();
        return true;
    }
    return false;
}

void IPPool::cleanup_expired_leases(std::chrono::seconds timeout) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    auto it = client_assignments_.begin();
    while (it != client_assignments_.end()) {
        if (it->second->is_expired(timeout)) {
            uint32_t ip = it->second->ip_numeric;
            allocated_ips_.erase(ip);
            ip_to_client_.erase(ip);
            it = client_assignments_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<std::string> IPPool::get_allocated_ips() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    std::vector<std::string> ips;
    for (const auto& pair : client_assignments_) {
        if (pair.second->is_active) {
            ips.push_back(pair.second->ip_address);
        }
    }
    return ips;
}

std::vector<ClientIPAssignment> IPPool::get_active_assignments() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    std::vector<ClientIPAssignment> assignments;
    for (const auto& pair : client_assignments_) {
        if (pair.second->is_active) {
            assignments.push_back(*pair.second);
        }
    }
    return assignments;
}

std::string IPPool::get_pool_info() const {
    std::ostringstream oss;
    oss << "IP Pool Information:\n";
    oss << "Total IPs: " << get_total_ips() << "\n";
    oss << "Allocated: " << get_allocated_count() << "\n";
    oss << "Available: " << get_available_count() << "\n";
    oss << "Utilization: " << get_utilization_percentage() << "%\n";
    return oss.str();
}

bool IPPool::add_range(const std::string& cidr) {
    try {
        auto range = std::make_unique<IPRange>(cidr);
        add_range_internal(std::move(range));
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<std::string> IPPool::get_ranges() const {
    std::vector<std::string> ranges;
    for (const auto& range : ip_ranges_) {
        ranges.push_back(range->network);
    }
    return ranges;
}

bool IPPool::save_to_file(const std::string& file_path) const {
    return true;
}

bool IPPool::load_from_file(const std::string& file_path) {
    return true;
}

bool IPPool::is_valid_ip_format(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

uint32_t IPPool::ip_string_to_numeric(const std::string& ip) {
    struct sockaddr_in sa;
    inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    return ntohl(sa.sin_addr.s_addr);
}

std::string IPPool::ip_numeric_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return inet_ntoa(addr);
}

uint32_t IPPool::find_next_available_ip() const {
    for (const auto& range : ip_ranges_) {
        for (uint32_t ip = range->start_ip + 1; ip < range->end_ip; ++ip) {
            if (allocated_ips_.count(ip) == 0) {
                return ip;
            }
        }
    }
    return 0;
}

bool IPPool::is_ip_in_ranges(uint32_t ip) const {
    for (const auto& range : ip_ranges_) {
        if (range->contains(ip)) {
            return true;
        }
    }
    return false;
}

void IPPool::add_range_internal(std::unique_ptr<IPRange> range) {
    ip_ranges_.push_back(std::move(range));
}

std::string IPPool::format_assignment_info(const ClientIPAssignment& assignment) const {
    std::ostringstream oss;
    oss << "Client: " << assignment.client_id;
    oss << ", IP: " << assignment.ip_address;
    oss << ", Active: " << (assignment.is_active ? "Yes" : "No");
    return oss.str();
}

std::pair<uint32_t, uint32_t> IPPool::parse_cidr_range(const std::string& cidr) {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        throw std::invalid_argument("Invalid CIDR format");
    }
    
    std::string network = cidr.substr(0, slash_pos);
    uint32_t prefix_len = std::stoul(cidr.substr(slash_pos + 1));
    
    uint32_t network_ip = ip_string_to_numeric(network);
    uint32_t mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF;
    
    uint32_t start_ip = network_ip & mask;
    uint32_t end_ip = start_ip | (~mask & 0xFFFFFFFF);
    
    return {start_ip, end_ip};
}

}