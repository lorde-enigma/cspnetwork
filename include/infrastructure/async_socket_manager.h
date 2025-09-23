#pragma once

#include <netinet/in.h>
#include <sys/epoll.h>
#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>
#include <thread>
#include <atomic>
#include "domain/types.h"

namespace CipherProxy::Infrastructure {

enum class SocketEventType {
    READ,
    WRITE,
    ERROR,
    DISCONNECT
};

struct SocketEvent {
    int socket_fd;
    SocketEventType type;
    std::vector<uint8_t> data;
    sockaddr_in6 client_addr;
};

using SocketEventCallback = std::function<void(const SocketEvent&)>;

class AsyncSocket {
private:
    int socket_fd_;
    sockaddr_in6 local_addr_;
    bool is_listening_;
    std::atomic<bool> is_connected_;

public:
    AsyncSocket(int socket_fd, const sockaddr_in6& local_addr);
    ~AsyncSocket();

    int get_fd() const { return socket_fd_; }
    const sockaddr_in6& get_local_addr() const { return local_addr_; }
    bool is_listening() const { return is_listening_; }
    bool is_connected() const { return is_connected_.load(); }

    void set_non_blocking();
    void set_socket_options();
    void set_listening(bool listening) { is_listening_ = listening; }
    void set_connected(bool connected) { is_connected_.store(connected); }
    
    ssize_t send_data(const std::vector<uint8_t>& data, const sockaddr_in6& dest_addr);
    ssize_t receive_data(std::vector<uint8_t>& buffer, sockaddr_in6& src_addr);
};

class ConnectionPool {
private:
    std::unordered_map<int, std::unique_ptr<AsyncSocket>> active_sockets_;
    std::vector<std::unique_ptr<AsyncSocket>> reusable_sockets_;
    size_t max_pool_size_;
    mutable std::mutex pool_mutex_;

public:
    explicit ConnectionPool(size_t max_size = 1000);
    ~ConnectionPool();

    std::unique_ptr<AsyncSocket> acquire_socket();
    void release_socket(std::unique_ptr<AsyncSocket> socket);
    void add_active_socket(int fd, std::unique_ptr<AsyncSocket> socket);
    void remove_active_socket(int fd);
    
    AsyncSocket* get_active_socket(int fd);
    size_t get_active_count() const;
    size_t get_pool_size() const;
    void cleanup_dead_connections();
};

class AsyncSocketManager {
private:
    int epoll_fd_;
    std::unique_ptr<ConnectionPool> connection_pool_;
    std::vector<std::thread> worker_threads_;
    
    SocketEventCallback event_callback_;
    
    std::vector<int> listening_sockets_;
    uint16_t base_port_;
    size_t num_listeners_;
    std::atomic<bool> running_;

    void worker_thread_loop();
    void handle_epoll_event(const epoll_event& event);
    void handle_new_connection(int listening_socket);
    void handle_socket_read(int socket_fd);
    void handle_socket_write(int socket_fd);
    void handle_socket_error(int socket_fd);

public:
    explicit AsyncSocketManager(uint16_t base_port = 1194, size_t num_listeners = 4);
    ~AsyncSocketManager();

    bool start();
    void stop();
    
    void set_event_callback(SocketEventCallback callback);
    
    bool bind_ipv6_listeners();
    void add_socket_to_epoll(int socket_fd, uint32_t events = EPOLLIN | EPOLLOUT | EPOLLET);
    void remove_socket_from_epoll(int socket_fd);
    
    bool send_to_client(const std::vector<uint8_t>& data, const sockaddr_in6& client_addr);
    
    size_t get_active_connections() const;
    std::vector<int> get_listening_ports() const;
    
    void set_socket_buffer_sizes(int socket_fd, int send_size = 262144, int recv_size = 262144);
    void enable_socket_reuse(int socket_fd);
    void set_keepalive(int socket_fd, int idle = 7200, int interval = 75, int count = 9);
};

class PacketBuffer {
private:
    std::vector<uint8_t> buffer_;
    size_t capacity_;
    size_t read_pos_;
    size_t write_pos_;
    std::mutex buffer_mutex_;

public:
    explicit PacketBuffer(size_t capacity = 65536);
    
    bool write(const std::vector<uint8_t>& data);
    bool read(std::vector<uint8_t>& data, size_t max_size);
    
    size_t available_space() const;
    size_t available_data() const;
    
    void compact();
    void clear();
    
    bool is_full() const;
    bool is_empty() const;
};

}
