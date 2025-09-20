#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>
#include <exception>
#include <chrono>
#include <thread>
#include <random>
#include <cmath>
#include <future>

namespace CipherProxy::Infrastructure {

enum class ErrorCategory {
    NETWORK,
    SECURITY,
    CONFIGURATION,
    SEEDING,
    AUTHENTICATION,
    ROUTING,
    MEMORY,
    FILESYSTEM,
    PROTOCOL,
    SYSTEM,
    UNKNOWN
};

enum class ErrorSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class RecoveryStrategy {
    NONE,
    RETRY,
    RESTART,
    FAILOVER,
    DEGRADE,
    ABORT
};

struct ErrorDetails {
    std::string error_id;
    std::string component;
    std::string message;
    std::string technical_details;
    ErrorCategory category;
    ErrorSeverity severity;
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, std::string> context;
    std::string stack_trace;
    bool is_recoverable;
    RecoveryStrategy suggested_recovery;
    
    ErrorDetails() 
        : category(ErrorCategory::UNKNOWN)
        , severity(ErrorSeverity::LOW)
        , timestamp(std::chrono::system_clock::now())
        , is_recoverable(true)
        , suggested_recovery(RecoveryStrategy::NONE) {}
};

using ErrorHandler = std::function<bool(const ErrorDetails&)>;
using RecoveryHandler = std::function<bool(const ErrorDetails&)>;

class ErrorHandlerManager {
public:
    static ErrorHandlerManager& instance();
    
    void initialize();
    void shutdown();
    
    void register_error_handler(ErrorCategory category, ErrorHandler handler);
    void register_recovery_handler(RecoveryStrategy strategy, RecoveryHandler handler);
    
    void report_error(const ErrorDetails& error);
    void report_error(const std::string& component, const std::string& message, 
                     ErrorCategory category = ErrorCategory::UNKNOWN,
                     ErrorSeverity severity = ErrorSeverity::MEDIUM);
    
    bool handle_error(const ErrorDetails& error);
    bool attempt_recovery(const ErrorDetails& error);
    
    std::vector<ErrorDetails> get_recent_errors(size_t count = 100) const;
    std::vector<ErrorDetails> get_errors_by_category(ErrorCategory category) const;
    std::vector<ErrorDetails> get_errors_by_severity(ErrorSeverity severity) const;
    
    void clear_error_history();
    
    size_t get_error_count() const;
    size_t get_error_count_by_category(ErrorCategory category) const;
    
    void set_max_error_history(size_t max_size);
    void enable_error_aggregation(bool enable);
    
    std::string error_category_to_string(ErrorCategory category) const;
    std::string error_severity_to_string(ErrorSeverity severity) const;
    std::string recovery_strategy_to_string(RecoveryStrategy strategy) const;
    
    ErrorCategory string_to_error_category(const std::string& category) const;
    ErrorSeverity string_to_error_severity(const std::string& severity) const;
    RecoveryStrategy string_to_recovery_strategy(const std::string& strategy) const;

private:
    ErrorHandlerManager() = default;
    ~ErrorHandlerManager() = default;
    
    void log_error(const ErrorDetails& error) const;
    void aggregate_similar_errors(const ErrorDetails& error);
    bool is_similar_error(const ErrorDetails& error1, const ErrorDetails& error2) const;
    std::string generate_error_id(const ErrorDetails& error) const;

public:
    std::string capture_stack_trace() const;

private:
    
    mutable std::mutex error_mutex_;
    std::atomic<bool> initialized_{false};
    
    std::unordered_map<ErrorCategory, ErrorHandler> error_handlers_;
    std::unordered_map<RecoveryStrategy, RecoveryHandler> recovery_handlers_;
    
    std::vector<ErrorDetails> error_history_;
    std::unordered_map<std::string, std::vector<ErrorDetails>> aggregated_errors_;
    
    size_t max_error_history_{1000};
    std::atomic<bool> error_aggregation_enabled_{true};
    std::atomic<size_t> total_error_count_{0};
};

class VPNException : public std::exception {
public:
    VPNException(const std::string& message, ErrorCategory category = ErrorCategory::UNKNOWN,
                 ErrorSeverity severity = ErrorSeverity::MEDIUM)
        : message_(message), category_(category), severity_(severity) {
        
        ErrorDetails error;
        error.message = message;
        error.category = category;
        error.severity = severity;
        error.timestamp = std::chrono::system_clock::now();
        error.stack_trace = ErrorHandlerManager::instance().capture_stack_trace();
        
        ErrorHandlerManager::instance().report_error(error);
    }
    
    const char* what() const noexcept override {
        return message_.c_str();
    }
    
    ErrorCategory get_category() const { return category_; }
    ErrorSeverity get_severity() const { return severity_; }

private:
    std::string message_;
    ErrorCategory category_;
    ErrorSeverity severity_;
};

class NetworkException : public VPNException {
public:
    NetworkException(const std::string& message) 
        : VPNException(message, ErrorCategory::NETWORK, ErrorSeverity::HIGH) {}
};

class SecurityException : public VPNException {
public:
    SecurityException(const std::string& message) 
        : VPNException(message, ErrorCategory::SECURITY, ErrorSeverity::CRITICAL) {}
};

class ConfigurationException : public VPNException {
public:
    ConfigurationException(const std::string& message) 
        : VPNException(message, ErrorCategory::CONFIGURATION, ErrorSeverity::HIGH) {}
};

class SeedingException : public VPNException {
public:
    SeedingException(const std::string& message) 
        : VPNException(message, ErrorCategory::SEEDING, ErrorSeverity::MEDIUM) {}
};

class AuthenticationException : public VPNException {
public:
    AuthenticationException(const std::string& message) 
        : VPNException(message, ErrorCategory::AUTHENTICATION, ErrorSeverity::HIGH) {}
};

class RoutingException : public VPNException {
public:
    RoutingException(const std::string& message) 
        : VPNException(message, ErrorCategory::ROUTING, ErrorSeverity::MEDIUM) {}
};

class MemoryException : public VPNException {
public:
    MemoryException(const std::string& message) 
        : VPNException(message, ErrorCategory::MEMORY, ErrorSeverity::CRITICAL) {}
};

class ProtocolException : public VPNException {
public:
    ProtocolException(const std::string& message) 
        : VPNException(message, ErrorCategory::PROTOCOL, ErrorSeverity::HIGH) {}
};

class SystemException : public VPNException {
public:
    SystemException(const std::string& message) 
        : VPNException(message, ErrorCategory::SYSTEM, ErrorSeverity::CRITICAL) {}
};

#define THROW_NETWORK_ERROR(msg) throw NetworkException(msg)
#define THROW_SECURITY_ERROR(msg) throw SecurityException(msg)
#define THROW_CONFIG_ERROR(msg) throw ConfigurationException(msg)
#define THROW_SEEDING_ERROR(msg) throw SeedingException(msg)
#define THROW_AUTH_ERROR(msg) throw AuthenticationException(msg)
#define THROW_ROUTING_ERROR(msg) throw RoutingException(msg)
#define THROW_MEMORY_ERROR(msg) throw MemoryException(msg)
#define THROW_PROTOCOL_ERROR(msg) throw ProtocolException(msg)
#define THROW_SYSTEM_ERROR(msg) throw SystemException(msg)

#define REPORT_ERROR(component, message, category, severity) \
    ErrorHandlerManager::instance().report_error(component, message, category, severity)

#define HANDLE_EXCEPTION(block) \
    try { \
        block \
    } catch (const VPNException& e) { \
        ErrorDetails error; \
        error.component = __FUNCTION__; \
        error.message = e.what(); \
        error.category = e.get_category(); \
        error.severity = e.get_severity(); \
        error.timestamp = std::chrono::system_clock::now(); \
        ErrorHandlerManager::instance().handle_error(error); \
    } catch (const std::exception& e) { \
        ErrorDetails error; \
        error.component = __FUNCTION__; \
        error.message = e.what(); \
        error.category = ErrorCategory::UNKNOWN; \
        error.severity = ErrorSeverity::HIGH; \
        error.timestamp = std::chrono::system_clock::now(); \
        ErrorHandlerManager::instance().handle_error(error); \
    }

class CircuitBreaker {
public:
    enum class State {
        CLOSED,
        OPEN,
        HALF_OPEN
    };
    
    CircuitBreaker(size_t failure_threshold = 5, 
                   std::chrono::milliseconds timeout = std::chrono::milliseconds(30000))
        : failure_threshold_(failure_threshold)
        , timeout_(timeout)
        , state_(State::CLOSED)
        , failure_count_(0)
        , last_failure_time_(std::chrono::steady_clock::now()) {}
    
    template<typename F>
    auto execute(F&& func) -> decltype(func()) {
        if (state_ == State::OPEN) {
            if (should_attempt_reset()) {
                state_ = State::HALF_OPEN;
            } else {
                throw VPNException("circuit breaker is open", ErrorCategory::SYSTEM, ErrorSeverity::HIGH);
            }
        }
        
        try {
            auto result = func();
            on_success();
            return result;
        } catch (...) {
            on_failure();
            throw;
        }
    }
    
    State get_state() const { return state_; }
    size_t get_failure_count() const { return failure_count_; }

private:
    void on_success() {
        failure_count_ = 0;
        state_ = State::CLOSED;
    }
    
    void on_failure() {
        failure_count_++;
        last_failure_time_ = std::chrono::steady_clock::now();
        
        if (failure_count_ >= failure_threshold_) {
            state_ = State::OPEN;
        }
    }
    
    bool should_attempt_reset() const {
        return std::chrono::steady_clock::now() - last_failure_time_ > timeout_;
    }
    
    size_t failure_threshold_;
    std::chrono::milliseconds timeout_;
    std::atomic<State> state_;
    std::atomic<size_t> failure_count_;
    std::chrono::steady_clock::time_point last_failure_time_;
};

class RetryPolicy {
public:
    struct RetryConfig {
        size_t max_attempts{3};
        std::chrono::milliseconds base_delay{100};
        double backoff_multiplier{2.0};
        std::chrono::milliseconds max_delay{5000};
        bool enable_jitter{true};
    };
    
    RetryPolicy() : config_{} {}
    RetryPolicy(const RetryConfig& config) : config_(config) {}
    
    template<typename F>
    auto execute(F&& func) -> decltype(func()) {
        std::exception_ptr last_exception;
        
        for (size_t attempt = 0; attempt < config_.max_attempts; ++attempt) {
            try {
                return func();
            } catch (...) {
                last_exception = std::current_exception();
                
                if (attempt + 1 < config_.max_attempts) {
                    auto delay = calculate_delay(attempt);
                    std::this_thread::sleep_for(delay);
                }
            }
        }
        
        if (last_exception) {
            std::rethrow_exception(last_exception);
        }
        
        throw VPNException("retry policy exhausted without success", 
                          ErrorCategory::SYSTEM, ErrorSeverity::HIGH);
    }

private:
    std::chrono::milliseconds calculate_delay(size_t attempt) const {
        auto delay = static_cast<double>(config_.base_delay.count()) * 
                    std::pow(config_.backoff_multiplier, attempt);
        
        delay = std::min(delay, static_cast<double>(config_.max_delay.count()));
        
        if (config_.enable_jitter) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_real_distribution<> dis(0.5, 1.5);
            delay *= dis(gen);
        }
        
        return std::chrono::milliseconds(static_cast<long long>(delay));
    }
    
    RetryConfig config_;
};

class Bulkhead {
public:
    Bulkhead(size_t max_concurrent_operations = 10)
        : max_operations_(max_concurrent_operations), current_operations_(0) {}
    
    template<typename F>
    auto execute(F&& func) -> decltype(func()) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (current_operations_ >= max_operations_) {
            throw std::runtime_error("max concurrent operations exceeded");
        }
        ++current_operations_;
        lock.unlock();
        
        try {
            auto result = func();
            lock.lock();
            --current_operations_;
            return result;
        } catch (...) {
            lock.lock();
            --current_operations_;
            throw;
        }
    }

private:
    size_t max_operations_;
    std::atomic<size_t> current_operations_;
    std::mutex mutex_;
};

class Timeout {
public:
    template<typename F>
    static auto execute(F&& func, std::chrono::milliseconds) -> decltype(func()) {
        return func();
    }
};

}
