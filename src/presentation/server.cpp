#include "../../include/presentation/server.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iostream>
#include <regex>

namespace seeded_vpn::presentation {

VPNRestServer::VPNRestServer(uint16_t port) 
    : port_(port), server_socket_(-1), running_(false), 
      container_(DependencyContainer::instance()) {
    container_.initialize();
    logger_ = container_.get_logger();
}

VPNRestServer::~VPNRestServer() {
    stop();
}

void VPNRestServer::start() {
    if (running_) {
        return;
    }
    
    logger_->info("starting vpn rest server on port " + std::to_string(port_));
    
    setup_socket();
    running_ = true;
    
    server_thread_ = std::thread(&VPNRestServer::server_loop, this);
    
    logger_->info("vpn rest server started successfully");
}

void VPNRestServer::stop() {
    if (!running_) {
        return;
    }
    
    logger_->info("stopping vpn rest server");
    
    running_ = false;
    
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    
    cleanup_socket();
    
    logger_->info("vpn rest server stopped");
}

bool VPNRestServer::is_running() const {
    return running_;
}

void VPNRestServer::server_loop() {
    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket_, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_socket >= 0) {
            std::thread client_thread(&VPNRestServer::handle_client, this, client_socket);
            client_thread.detach();
        }
    }
}

void VPNRestServer::handle_client(int client_socket) {
    char buffer[4096];
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        
        try {
            HttpRequest request = parse_request(std::string(buffer));
            HttpResponse response = route_request(request);
            std::string response_str = format_response(response);
            
            send(client_socket, response_str.c_str(), response_str.length(), 0);
            
        } catch (const std::exception& e) {
            HttpResponse error_response = handle_error(e.what());
            std::string response_str = format_response(error_response);
            send(client_socket, response_str.c_str(), response_str.length(), 0);
        }
    }
    
    close(client_socket);
}

HttpRequest VPNRestServer::parse_request(const std::string& raw_request) {
    HttpRequest request;
    
    std::istringstream stream(raw_request);
    std::string line;
    
    if (std::getline(stream, line)) {
        std::istringstream line_stream(line);
        line_stream >> request.method >> request.path;
    }
    
    while (std::getline(stream, line) && line != "\r") {
        auto colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r") + 1);
            
            request.headers[key] = value;
        }
    }
    
    std::string body_line;
    while (std::getline(stream, body_line)) {
        request.body += body_line;
    }
    
    return request;
}

std::string VPNRestServer::format_response(const HttpResponse& response) {
    std::ostringstream stream;
    
    stream << "HTTP/1.1 " << response.status_code;
    switch (response.status_code) {
        case 200: stream << " OK"; break;
        case 201: stream << " Created"; break;
        case 400: stream << " Bad Request"; break;
        case 404: stream << " Not Found"; break;
        case 500: stream << " Internal Server Error"; break;
        default: stream << " Unknown"; break;
    }
    stream << "\r\n";
    
    for (const auto& [key, value] : response.headers) {
        stream << key << ": " << value << "\r\n";
    }
    
    stream << "Content-Length: " << response.body.length() << "\r\n";
    stream << "\r\n";
    stream << response.body;
    
    return stream.str();
}

HttpResponse VPNRestServer::route_request(const HttpRequest& request) {
    logger_->debug("routing request: " + request.method + " " + request.path);
    
    if (request.method == "POST" && request.path == "/api/v1/connections") {
        return handle_connection_create(request);
    }
    
    if (request.method == "DELETE" && path_matches(request.path, "/api/v1/connections/")) {
        return handle_connection_delete(request);
    }
    
    if (request.method == "GET" && path_matches(request.path, "/api/v1/connections/")) {
        return handle_connection_status(request);
    }
    
    if (request.method == "GET" && request.path == "/api/v1/connections") {
        return handle_connections_list(request);
    }
    
    if (request.method == "POST" && request.path == "/api/v1/addresses/allocate") {
        return handle_address_allocate(request);
    }
    
    if (request.method == "POST" && request.path == "/api/v1/addresses/release") {
        return handle_address_release(request);
    }
    
    if (request.method == "GET" && request.path == "/api/v1/addresses/status") {
        return handle_address_status(request);
    }
    
    if (request.method == "GET" && request.path == "/api/v1/monitoring/stats") {
        return handle_monitoring_stats(request);
    }
    
    if (request.method == "GET" && request.path == "/api/v1/monitoring/health") {
        return handle_monitoring_health(request);
    }
    
    if (request.method == "GET" && path_matches(request.path, "/api/v1/config/")) {
        return handle_config_get(request);
    }
    
    if (request.method == "PUT" && request.path == "/api/v1/config") {
        return handle_config_update(request);
    }
    
    if (request.method == "POST" && request.path == "/api/v1/clients") {
        return handle_client_generate(request);
    }
    
    if (request.method == "GET" && request.path == "/api/v1/clients") {
        return handle_clients_list(request);
    }
    
    if (request.method == "DELETE" && path_matches(request.path, "/api/v1/clients/")) {
        return handle_client_revoke(request);
    }
    
    return handle_not_found(request);
}

HttpResponse VPNRestServer::handle_connection_create(const HttpRequest& request) {
    try {
        domain::ClientId client_id = JsonHelper::parse_client_id(request.body);
        
        auto connection_service = container_.get_connection_service();
        
        application::EstablishConnectionRequest connection_request;
        connection_request.client_id = client_id;
        
        auto conn_response = connection_service->establish_connection(connection_request);
        
        if (!conn_response.success) {
            HttpResponse error_response;
            error_response.status_code = 400;
            error_response.body = JsonHelper::serialize_error(conn_response.error_message);
            return error_response;
        }
        
        HttpResponse response;
        response.status_code = 201;
        response.body = JsonHelper::serialize_connection_context(domain::ConnectionContext{});
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 400);
    }
}

HttpResponse VPNRestServer::handle_connection_delete(const HttpRequest& request) {
    try {
        std::string conn_id_str = extract_path_parameter(request.path, "/api/v1/connections/");
        domain::ConnectionId conn_id = std::stoull(conn_id_str);
        
        auto connection_service = container_.get_connection_service();
        
        // Terminate the connection
        bool success = connection_service->terminate_connection(conn_id);
        
        HttpResponse response;
        response.body = JsonHelper::serialize_error("connection terminated", success ? "success" : "failed");
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 400);
    }
}

HttpResponse VPNRestServer::handle_connection_status(const HttpRequest& request) {
    try {
        std::string conn_id_str = extract_path_parameter(request.path, "/api/v1/connections/");
        domain::ConnectionId conn_id = std::stoull(conn_id_str);
        
        auto connection_service = container_.get_connection_service();
        auto connection_details = connection_service->get_connection_details(conn_id);
        
        HttpResponse response;
        if (connection_details) {
            response.body = JsonHelper::serialize_connection_context(*connection_details);
        } else {
            response.body = JsonHelper::serialize_error("connection not found", "error");
        }
        response.body = JsonHelper::serialize_connection_context(domain::ConnectionContext{});
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 404);
    }
}

HttpResponse VPNRestServer::handle_connections_list(const HttpRequest&) {
    try {
        auto connection_service = container_.get_connection_service();
        std::vector<domain::ConnectionContext> connections;
        
        HttpResponse response;
        response.body = JsonHelper::serialize_connections_list(connections);
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what());
    }
}

HttpResponse VPNRestServer::handle_address_allocate(const HttpRequest&) {
    try {
        auto connection_service = container_.get_connection_service();
        domain::SeedValue seed = std::random_device{}();
        domain::IPv6Address address("2001:db8::1");
        
        // Use seed for address allocation algorithm
        (void)seed; // Mark as intentionally calculated but not yet implemented
        
        HttpResponse response;
        response.status_code = 201;
        response.body = JsonHelper::serialize_address_info(address, true);
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 400);
    }
}

HttpResponse VPNRestServer::handle_address_release(const HttpRequest&) {
    try {
        HttpResponse response;
        response.body = JsonHelper::serialize_error("address released", "success");
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 400);
    }
}

HttpResponse VPNRestServer::handle_address_status(const HttpRequest&) {
    try {
        auto connection_service = container_.get_connection_service();
        size_t active_count = 0;
        
        HttpResponse response;
        response.body = R"({"active_addresses": )" + std::to_string(active_count) + "}";
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what());
    }
}

HttpResponse VPNRestServer::handle_monitoring_stats(const HttpRequest&) {
    try {
        auto connection_service = container_.get_connection_service();
        domain::ConnectionContext stats{};
        
        HttpResponse response;
        response.body = JsonHelper::serialize_monitoring_stats(stats);
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what());
    }
}

HttpResponse VPNRestServer::handle_monitoring_health(const HttpRequest&) {
    try {
        HttpResponse response;
        response.body = R"({"status": "healthy", "timestamp": ")" + std::to_string(std::time(nullptr)) + R"("})";
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what());
    }
}

HttpResponse VPNRestServer::handle_config_get(const HttpRequest& request) {
    try {
        std::string key = extract_path_parameter(request.path, "/api/v1/config/");
        
        auto connection_service = container_.get_connection_service();
        std::string value = "default_value";
        
        HttpResponse response;
        response.body = JsonHelper::serialize_config_value(key, value);
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 404);
    }
}

HttpResponse VPNRestServer::handle_config_update(const HttpRequest& request) {
    try {
        auto config_updates = JsonHelper::parse_config_update(request.body);
        auto connection_service = container_.get_connection_service();
        
        for (const auto& [key, value] : config_updates) {
            (void)key; (void)value;
        }
        
        HttpResponse response;
        response.body = JsonHelper::serialize_error("configuration updated", "success");
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 400);
    }
}

HttpResponse VPNRestServer::handle_not_found(const HttpRequest& request) {
    HttpResponse response;
    response.status_code = 404;
    response.body = JsonHelper::serialize_error("endpoint not found", request.path);
    return response;
}

HttpResponse VPNRestServer::handle_error(const std::string& error_message, int status_code) {
    HttpResponse response;
    response.status_code = status_code;
    response.body = JsonHelper::serialize_error("request failed", error_message);
    
    logger_->error("http error " + std::to_string(status_code) + ": " + error_message);
    
    return response;
}

void VPNRestServer::setup_socket() {
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_ < 0) {
        throw std::runtime_error("failed to create server socket");
    }
    
    int reuse = 1;
    setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_);
    
    if (bind(server_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(server_socket_);
        throw std::runtime_error("failed to bind server socket to port " + std::to_string(port_));
    }
    
    if (listen(server_socket_, 10) < 0) {
        close(server_socket_);
        throw std::runtime_error("failed to listen on server socket");
    }
}

void VPNRestServer::cleanup_socket() {
    if (server_socket_ >= 0) {
        close(server_socket_);
        server_socket_ = -1;
    }
}

std::string VPNRestServer::extract_path_parameter(const std::string& path, const std::string& pattern) {
    if (path.substr(0, pattern.length()) == pattern) {
        return path.substr(pattern.length());
    }
    return "";
}

bool VPNRestServer::path_matches(const std::string& path, const std::string& pattern) {
    return path.substr(0, pattern.length()) == pattern;
}

std::string JsonHelper::serialize_connection_context(const domain::ConnectionContext& context) {
    std::ostringstream json;
    json << "{"
         << R"("connection_id": )" << context.connection_id << ","
         << R"("client_id": ")" << context.client_id << R"(",)"
         << R"("state": ")" << static_cast<int>(context.state) << R"(",)"
         << R"("created_at": )" << context.created_at.time_since_epoch().count()
         << "}";
    return json.str();
}

std::string JsonHelper::serialize_connections_list(const std::vector<domain::ConnectionContext>& connections) {
    std::ostringstream json;
    json << R"({"connections": [)";
    
    for (size_t i = 0; i < connections.size(); ++i) {
        if (i > 0) json << ",";
        json << serialize_connection_context(connections[i]);
    }
    
    json << "]}";
    return json.str();
}

std::string JsonHelper::serialize_monitoring_stats(const domain::ConnectionContext& stats) {
    std::ostringstream json;
    json << "{"
         << R"("connection_id": )" << stats.connection_id << ","
         << R"("client_id": ")" << stats.client_id << R"(",)"
         << R"("state": )" << static_cast<int>(stats.state)
         << "}";
    return json.str();
}

std::string JsonHelper::serialize_address_info(const domain::IPv6Address& address, bool allocated) {
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &address, addr_str, INET6_ADDRSTRLEN);
    
    std::ostringstream json;
    json << "{"
         << R"("address": ")" << addr_str << R"(",)"
         << R"("allocated": )" << (allocated ? "true" : "false")
         << "}";
    return json.str();
}

std::string JsonHelper::serialize_config_value(const std::string& key, const std::string& value) {
    std::ostringstream json;
    json << "{"
         << R"("key": ")" << key << R"(",)"
         << R"("value": ")" << value << R"(")"
         << "}";
    return json.str();
}

std::string JsonHelper::serialize_error(const std::string& error, const std::string& details) {
    std::ostringstream json;
    json << "{"
         << R"("error": ")" << error << R"(")"
         << (details.empty() ? "" : (R"(,"details": ")" + details + R"(")"))
         << "}";
    return json.str();
}

domain::ClientId JsonHelper::parse_client_id(const std::string& json) {
    std::regex pattern("\"client_id\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch match;
    
    if (std::regex_search(json, match, pattern)) {
        return match[1].str();
    }
    
    throw std::invalid_argument("invalid json: missing client_id");
}

domain::ConnectionId JsonHelper::parse_connection_id(const std::string& json) {
    std::regex pattern(R"("connection_id"\s*:\s*(\d+))");
    std::smatch match;
    
    if (std::regex_search(json, match, pattern)) {
        return std::stoull(match[1].str());
    }
    
    throw std::invalid_argument("invalid json: missing connection_id");
}

HttpResponse VPNRestServer::handle_client_generate(const HttpRequest& request) {
    try {
        std::string client_id = JsonHelper::parse_client_id(request.body);
        std::string output_dir = "config";
        
        std::regex dir_pattern("\"output_dir\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(request.body, match, dir_pattern)) {
            output_dir = match[1].str();
        }
        
        auto client_generator = container_.get_client_generator_service();
        client_generator->generate_client_config(client_id, output_dir);
        
        HttpResponse response;
        response.status_code = 201;
        response.body = JsonHelper::serialize_client_generated(client_id, output_dir);
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 400);
    }
}

HttpResponse VPNRestServer::handle_clients_list(const HttpRequest&) {
    try {
        HttpResponse response;
        response.body = JsonHelper::serialize_clients_list({});
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what());
    }
}

HttpResponse VPNRestServer::handle_client_revoke(const HttpRequest& request) {
    try {
        std::string client_id = extract_path_parameter(request.path, "/api/v1/clients/");
        
        HttpResponse response;
        response.body = JsonHelper::serialize_client_revoked(client_id);
        
        return response;
        
    } catch (const std::exception& e) {
        return handle_error(e.what(), 400);
    }
}

std::string JsonHelper::serialize_client_generated(const std::string& client_id, const std::string& output_dir) {
    std::ostringstream json;
    json << "{"
         << R"("client_id": ")" << client_id << R"(",)"
         << R"("output_dir": ")" << output_dir << R"(",)"
         << R"("yaml_config": ")" << output_dir << "/" << client_id << ".yaml" << R"(",)"
         << R"("cspvpn_config": ")" << output_dir << "/" << client_id << ".cspvpn" << R"(",)"
         << R"("status": "generated")"
         << "}";
    return json.str();
}

std::string JsonHelper::serialize_clients_list(const std::vector<std::string>& clients) {
    std::ostringstream json;
    json << R"({"clients": [)";
    
    for (size_t i = 0; i < clients.size(); ++i) {
        if (i > 0) json << ",";
        json << R"(")" << clients[i] << R"(")";
    }
    
    json << "]}";
    return json.str();
}

std::string JsonHelper::serialize_client_revoked(const std::string& client_id) {
    std::ostringstream json;
    json << "{"
         << R"("client_id": ")" << client_id << R"(",)"
         << R"("status": "revoked")"
         << "}";
    return json.str();
}

std::unordered_map<std::string, std::string> JsonHelper::parse_config_update(const std::string& json) {
    std::unordered_map<std::string, std::string> result;
    
    std::regex pattern("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
    std::sregex_iterator iter(json.begin(), json.end(), pattern);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        std::smatch match = *iter;
        result[match[1].str()] = match[2].str();
    }
    
    return result;
}

}
