#pragma once

#include "../domain/types.h"
#include "container.h"
#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <unordered_map>

namespace seeded_vpn::presentation {

struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
};

struct HttpResponse {
    int status_code = 200;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    
    HttpResponse() {
        headers["Content-Type"] = "application/json";
        headers["Server"] = "cspnetwork/1.0";
    }
};

using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;

class VPNRestServer {
public:
    VPNRestServer(uint16_t port = 8080);
    ~VPNRestServer();
    
    void start();
    void stop();
    bool is_running() const;
    
private:
    uint16_t port_;
    int server_socket_;
    std::atomic<bool> running_;
    std::thread server_thread_;
    
    DependencyContainer& container_;
    std::shared_ptr<domain::ILogger> logger_;
    
    void server_loop();
    void handle_client(int client_socket);
    HttpRequest parse_request(const std::string& raw_request);
    std::string format_response(const HttpResponse& response);
    
    HttpResponse route_request(const HttpRequest& request);
    
    HttpResponse handle_connection_create(const HttpRequest& request);
    HttpResponse handle_connection_delete(const HttpRequest& request);
    HttpResponse handle_connection_status(const HttpRequest& request);
    HttpResponse handle_connections_list(const HttpRequest& request);
    
    HttpResponse handle_address_allocate(const HttpRequest& request);
    HttpResponse handle_address_release(const HttpRequest& request);
    HttpResponse handle_address_status(const HttpRequest& request);
    
    HttpResponse handle_monitoring_stats(const HttpRequest& request);
    HttpResponse handle_monitoring_health(const HttpRequest& request);
    
    HttpResponse handle_config_get(const HttpRequest& request);
    HttpResponse handle_config_update(const HttpRequest& request);
    
    HttpResponse handle_client_generate(const HttpRequest& request);
    HttpResponse handle_clients_list(const HttpRequest& request);
    HttpResponse handle_client_revoke(const HttpRequest& request);
    
    HttpResponse handle_not_found(const HttpRequest& request);
    HttpResponse handle_error(const std::string& error_message, int status_code = 500);
    
    void setup_socket();
    void cleanup_socket();
    
    std::string extract_path_parameter(const std::string& path, const std::string& pattern);
    bool path_matches(const std::string& path, const std::string& pattern);
};

class JsonHelper {
public:
    static std::string serialize_connection_context(const domain::ConnectionContext& context);
    static std::string serialize_connections_list(const std::vector<domain::ConnectionContext>& connections);
    static std::string serialize_monitoring_stats(const domain::ConnectionContext& stats);
    static std::string serialize_address_info(const domain::IPv6Address& address, bool allocated = true);
    static std::string serialize_config_value(const std::string& key, const std::string& value);
    static std::string serialize_error(const std::string& error, const std::string& details = "");
    static std::string serialize_client_generated(const std::string& client_id, const std::string& output_dir);
    static std::string serialize_clients_list(const std::vector<std::string>& clients);
    static std::string serialize_client_revoked(const std::string& client_id);
    
    static domain::ClientId parse_client_id(const std::string& json);
    static domain::ConnectionId parse_connection_id(const std::string& json);
    static std::unordered_map<std::string, std::string> parse_config_update(const std::string& json);
};

}
