#include "infrastructure/async_socket_manager.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <algorithm>

namespace CipherProxy::Infrastructure {

AsyncSocket::AsyncSocket(int socket_fd, const sockaddr_in6& local_addr)
    : socket_fd_(socket_fd), local_addr_(local_addr), is_listening_(false), is_connected_(false) {
    set_non_blocking();
    set_socket_options();
}

AsyncSocket::~AsyncSocket() {
    if (socket_fd_ != -1) {
        close(socket_fd_);
    }
}

void AsyncSocket::set_non_blocking() {
    int flags = fcntl(socket_fd_, F_GETFL, 0);
    if (flags == -1) return;
    fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK);
}

void AsyncSocket::set_socket_options() {
    int opt = 1;
    setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    int ipv6_only = 1;
    setsockopt(socket_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only));
}

ssize_t AsyncSocket::send_data(const std::vector<uint8_t>& data, const sockaddr_in6& dest_addr) {
    return sendto(socket_fd_, data.data(), data.size(), 0, 
                  reinterpret_cast<const sockaddr*>(&dest_addr), sizeof(dest_addr));
}

ssize_t AsyncSocket::receive_data(std::vector<uint8_t>& buffer, sockaddr_in6& src_addr) {
    socklen_t addr_len = sizeof(src_addr);
    ssize_t bytes_received = recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                      reinterpret_cast<sockaddr*>(&src_addr), &addr_len);
    
    if (bytes_received > 0) {
        buffer.resize(bytes_received);
    }
    
    return bytes_received;
}

ConnectionPool::ConnectionPool(size_t max_size) : max_pool_size_(max_size) {}

ConnectionPool::~ConnectionPool() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    active_sockets_.clear();
    reusable_sockets_.clear();
}

std::unique_ptr<AsyncSocket> ConnectionPool::acquire_socket() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    if (!reusable_sockets_.empty()) {
        auto socket = std::move(reusable_sockets_.back());
        reusable_sockets_.pop_back();
        return socket;
    }
    
    return nullptr;
}

void ConnectionPool::release_socket(std::unique_ptr<AsyncSocket> socket) {
    if (!socket || !socket->is_connected()) return;
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    if (reusable_sockets_.size() < max_pool_size_) {
        socket->set_connected(false);
        reusable_sockets_.push_back(std::move(socket));
    }
}

void ConnectionPool::add_active_socket(int fd, std::unique_ptr<AsyncSocket> socket) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    active_sockets_[fd] = std::move(socket);
}

void ConnectionPool::remove_active_socket(int fd) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    active_sockets_.erase(fd);
}

AsyncSocket* ConnectionPool::get_active_socket(int fd) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    auto it = active_sockets_.find(fd);
    return (it != active_sockets_.end()) ? it->second.get() : nullptr;
}

size_t ConnectionPool::get_active_count() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return active_sockets_.size();
}

size_t ConnectionPool::get_pool_size() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return reusable_sockets_.size();
}

void ConnectionPool::cleanup_dead_connections() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    auto it = active_sockets_.begin();
    while (it != active_sockets_.end()) {
        if (!it->second->is_connected()) {
            it = active_sockets_.erase(it);
        } else {
            ++it;
        }
    }
}

AsyncSocketManager::AsyncSocketManager(uint16_t base_port, size_t num_listeners)
    : epoll_fd_(-1), base_port_(base_port), num_listeners_(num_listeners), running_(false) {
    connection_pool_ = std::make_unique<ConnectionPool>();
}

AsyncSocketManager::~AsyncSocketManager() {
    stop();
}

bool AsyncSocketManager::start() {
    if (running_.load()) return false;
    
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ == -1) return false;
    
    if (!bind_ipv6_listeners()) {
        close(epoll_fd_);
        return false;
    }
    
    running_.store(true);
    
    size_t num_threads = std::thread::hardware_concurrency();
    worker_threads_.reserve(num_threads);
    
    for (size_t i = 0; i < num_threads; ++i) {
        worker_threads_.emplace_back(&AsyncSocketManager::worker_thread_loop, this);
    }
    
    return true;
}

void AsyncSocketManager::stop() {
    if (!running_.load()) return;
    
    running_.store(false);
    
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    
    for (int fd : listening_sockets_) {
        close(fd);
    }
    listening_sockets_.clear();
    
    if (epoll_fd_ != -1) {
        close(epoll_fd_);
        epoll_fd_ = -1;
    }
}

bool AsyncSocketManager::bind_ipv6_listeners() {
    for (size_t i = 0; i < num_listeners_; ++i) {
        int socket_fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (socket_fd == -1) continue;
        
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(base_port_ + i);
        
        auto async_socket = std::make_unique<AsyncSocket>(socket_fd, addr);
        async_socket->set_listening(true);
        
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            continue;
        }
        
        add_socket_to_epoll(socket_fd, EPOLLIN | EPOLLET);
        set_socket_buffer_sizes(socket_fd);
        enable_socket_reuse(socket_fd);
        
        connection_pool_->add_active_socket(socket_fd, std::move(async_socket));
        listening_sockets_.push_back(socket_fd);
    }
    
    return !listening_sockets_.empty();
}

void AsyncSocketManager::add_socket_to_epoll(int socket_fd, uint32_t events) {
    epoll_event event{};
    event.events = events;
    event.data.fd = socket_fd;
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, socket_fd, &event);
}

void AsyncSocketManager::remove_socket_from_epoll(int socket_fd) {
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, socket_fd, nullptr);
}

void AsyncSocketManager::worker_thread_loop() {
    std::vector<epoll_event> events(32);
    
    while (running_.load()) {
        int num_events = epoll_wait(epoll_fd_, events.data(), events.size(), 100);
        
        for (int i = 0; i < num_events; ++i) {
            handle_epoll_event(events[i]);
        }
        
        connection_pool_->cleanup_dead_connections();
    }
}

void AsyncSocketManager::handle_epoll_event(const epoll_event& event) {
    int fd = event.data.fd;
    
    if (event.events & EPOLLERR || event.events & EPOLLHUP) {
        handle_socket_error(fd);
        return;
    }
    
    AsyncSocket* socket = connection_pool_->get_active_socket(fd);
    if (!socket) return;
    
    if (socket->is_listening()) {
        handle_new_connection(fd);
    } else {
        if (event.events & EPOLLIN) {
            handle_socket_read(fd);
        }
        if (event.events & EPOLLOUT) {
            handle_socket_write(fd);
        }
    }
}

void AsyncSocketManager::handle_new_connection(int listening_socket) {
    AsyncSocket* listener = connection_pool_->get_active_socket(listening_socket);
    if (!listener) return;
    
    std::vector<uint8_t> buffer(65536);
    sockaddr_in6 client_addr{};
    
    ssize_t bytes_received = listener->receive_data(buffer, client_addr);
    if (bytes_received > 0) {
        SocketEvent event{
            .socket_fd = listening_socket,
            .type = SocketEventType::READ,
            .data = buffer,
            .client_addr = client_addr
        };
        
        if (event_callback_) {
            event_callback_(event);
        }
    }
}

void AsyncSocketManager::handle_socket_read(int socket_fd) {
    AsyncSocket* socket = connection_pool_->get_active_socket(socket_fd);
    if (!socket) return;
    
    std::vector<uint8_t> buffer(65536);
    sockaddr_in6 client_addr{};
    
    ssize_t bytes_received = socket->receive_data(buffer, client_addr);
    if (bytes_received > 0) {
        SocketEvent event{
            .socket_fd = socket_fd,
            .type = SocketEventType::READ,
            .data = buffer,
            .client_addr = client_addr
        };
        
        if (event_callback_) {
            event_callback_(event);
        }
    } else if (bytes_received == 0) {
        handle_socket_error(socket_fd);
    }
}

void AsyncSocketManager::handle_socket_write(int socket_fd) {
    SocketEvent event{
        .socket_fd = socket_fd,
        .type = SocketEventType::WRITE,
        .data = {},
        .client_addr = {}
    };
    
    if (event_callback_) {
        event_callback_(event);
    }
}

void AsyncSocketManager::handle_socket_error(int socket_fd) {
    SocketEvent event{
        .socket_fd = socket_fd,
        .type = SocketEventType::ERROR,
        .data = {},
        .client_addr = {}
    };
    
    if (event_callback_) {
        event_callback_(event);
    }
    
    remove_socket_from_epoll(socket_fd);
    connection_pool_->remove_active_socket(socket_fd);
}

void AsyncSocketManager::set_event_callback(SocketEventCallback callback) {
    event_callback_ = std::move(callback);
}

bool AsyncSocketManager::send_to_client(const std::vector<uint8_t>& data, const sockaddr_in6& client_addr) {
    if (listening_sockets_.empty()) return false;
    
    int socket_fd = listening_sockets_[0];
    AsyncSocket* socket = connection_pool_->get_active_socket(socket_fd);
    
    if (socket) {
        return socket->send_data(data, client_addr) > 0;
    }
    
    return false;
}

size_t AsyncSocketManager::get_active_connections() const {
    return connection_pool_->get_active_count();
}

std::vector<int> AsyncSocketManager::get_listening_ports() const {
    std::vector<int> ports;
    for (size_t i = 0; i < num_listeners_; ++i) {
        ports.push_back(base_port_ + i);
    }
    return ports;
}

void AsyncSocketManager::set_socket_buffer_sizes(int socket_fd, int send_size, int recv_size) {
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &send_size, sizeof(send_size));
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &recv_size, sizeof(recv_size));
}

void AsyncSocketManager::enable_socket_reuse(int socket_fd) {
    int opt = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

void AsyncSocketManager::set_keepalive(int socket_fd, int idle, int interval, int count) {
    int opt = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(socket_fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
}

PacketBuffer::PacketBuffer(size_t capacity) 
    : capacity_(capacity), read_pos_(0), write_pos_(0) {
    buffer_.resize(capacity);
}

bool PacketBuffer::write(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    
    if (data.size() > available_space()) {
        return false;
    }
    
    size_t to_end = capacity_ - write_pos_;
    if (data.size() <= to_end) {
        std::copy(data.begin(), data.end(), buffer_.begin() + write_pos_);
        write_pos_ = (write_pos_ + data.size()) % capacity_;
    } else {
        std::copy(data.begin(), data.begin() + to_end, buffer_.begin() + write_pos_);
        std::copy(data.begin() + to_end, data.end(), buffer_.begin());
        write_pos_ = data.size() - to_end;
    }
    
    return true;
}

bool PacketBuffer::read(std::vector<uint8_t>& data, size_t max_size) {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    
    size_t available = available_data();
    if (available == 0) return false;
    
    size_t to_read = std::min(available, max_size);
    data.resize(to_read);
    
    size_t to_end = capacity_ - read_pos_;
    if (to_read <= to_end) {
        std::copy(buffer_.begin() + read_pos_, buffer_.begin() + read_pos_ + to_read, data.begin());
        read_pos_ = (read_pos_ + to_read) % capacity_;
    } else {
        std::copy(buffer_.begin() + read_pos_, buffer_.begin() + capacity_, data.begin());
        std::copy(buffer_.begin(), buffer_.begin() + (to_read - to_end), data.begin() + to_end);
        read_pos_ = to_read - to_end;
    }
    
    return true;
}

size_t PacketBuffer::available_space() const {
    if (write_pos_ >= read_pos_) {
        return capacity_ - (write_pos_ - read_pos_) - 1;
    } else {
        return read_pos_ - write_pos_ - 1;
    }
}

size_t PacketBuffer::available_data() const {
    if (write_pos_ >= read_pos_) {
        return write_pos_ - read_pos_;
    } else {
        return capacity_ - (read_pos_ - write_pos_);
    }
}

void PacketBuffer::compact() {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    
    if (read_pos_ == 0) return;
    
    size_t data_size = available_data();
    if (data_size == 0) {
        read_pos_ = write_pos_ = 0;
        return;
    }
    
    std::vector<uint8_t> temp_data;
    read(temp_data, data_size);
    
    read_pos_ = 0;
    write_pos_ = 0;
    write(temp_data);
}

void PacketBuffer::clear() {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    read_pos_ = write_pos_ = 0;
}

bool PacketBuffer::is_full() const {
    return available_space() == 0;
}

bool PacketBuffer::is_empty() const {
    return available_data() == 0;
}

}
