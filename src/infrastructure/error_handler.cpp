#include "infrastructure/error_handler.h"
#include "infrastructure/monitoring_system.h"
#include <algorithm>
#include <cxxabi.h>
#include <execinfo.h>
#include <iomanip>
#include <random>
#include <sstream>
#include <thread>

namespace CipherProxy::Infrastructure {

ErrorHandlerManager &ErrorHandlerManager::instance() {
  static ErrorHandlerManager instance;
  return instance;
}

void ErrorHandlerManager::initialize() {
  if (initialized_.exchange(true)) {
    return;
  }

  register_error_handler(
      ErrorCategory::NETWORK, [this](const ErrorDetails &error) {
        log_error(error);
        if (error.severity >= ErrorSeverity::HIGH) {
          auto &monitoring = MonitoringManager::instance();
          auto &alert_manager = monitoring.get_alert_manager();
          alert_manager.create_alert(error.severity == ErrorSeverity::CRITICAL
                                         ? AlertManager::AlertSeverity::CRITICAL
                                         : AlertManager::AlertSeverity::WARNING,
                                     "network_error", error.message);
        }
        return true;
      });

  register_error_handler(
      ErrorCategory::SECURITY, [this](const ErrorDetails &error) {
        log_error(error);
        auto &monitoring = MonitoringManager::instance();
        auto &alert_manager = monitoring.get_alert_manager();
        alert_manager.create_alert(AlertManager::AlertSeverity::CRITICAL,
                                   "security_threat", error.message);

        if (error.severity == ErrorSeverity::CRITICAL) {
          monitoring.get_metrics_collector();
        }
        return true;
      });

  register_error_handler(
      ErrorCategory::CONFIGURATION, [this](const ErrorDetails &error) {
        log_error(error);
        if (error.severity >= ErrorSeverity::HIGH) {
          auto &monitoring = MonitoringManager::instance();
          auto &alert_manager = monitoring.get_alert_manager();
          alert_manager.create_alert(AlertManager::AlertSeverity::WARNING,
                                     "config_error", error.message);
        }
        return true;
      });

  register_error_handler(
      ErrorCategory::MEMORY, [this](const ErrorDetails &error) {
        log_error(error);
        auto &monitoring = MonitoringManager::instance();
        auto &alert_manager = monitoring.get_alert_manager();
        alert_manager.create_alert(AlertManager::AlertSeverity::CRITICAL,
                                   "memory_error", error.message);
        return true;
      });

  register_recovery_handler(
      RecoveryStrategy::RETRY, [](const ErrorDetails &error) {
        LOG_INFO(
            "error_recovery", "attempting retry recovery",
            {{"component", error.component}, {"error_id", error.error_id}});

        RetryPolicy retry;
        try {
          retry.execute([&error]() { return true; });
          return true;
        } catch (...) {
          return false;
        }
      });

  register_recovery_handler(
      RecoveryStrategy::RESTART, [](const ErrorDetails &error) {
        LOG_WARNING(
            "error_recovery", "attempting component restart",
            {{"component", error.component}, {"error_id", error.error_id}});

        return true;
      });

  register_recovery_handler(
      RecoveryStrategy::FAILOVER, [](const ErrorDetails &error) {
        LOG_WARNING(
            "error_recovery", "attempting failover",
            {{"component", error.component}, {"error_id", error.error_id}});

        return true;
      });

  register_recovery_handler(
      RecoveryStrategy::DEGRADE, [](const ErrorDetails &error) {
        LOG_INFO(
            "error_recovery", "switching to degraded mode",
            {{"component", error.component}, {"error_id", error.error_id}});

        return true;
      });

  LOG_INFO("error_handler", "error handler manager initialized");
}

void ErrorHandlerManager::shutdown() {
  if (!initialized_.exchange(false)) {
    return;
  }

  std::lock_guard<std::mutex> lock(error_mutex_);
  error_handlers_.clear();
  recovery_handlers_.clear();
  error_history_.clear();
  aggregated_errors_.clear();

  LOG_INFO("error_handler", "error handler manager shutdown");
}

void ErrorHandlerManager::register_error_handler(ErrorCategory category,
                                                 ErrorHandler handler) {
  std::lock_guard<std::mutex> lock(error_mutex_);
  error_handlers_[category] = handler;
}

void ErrorHandlerManager::register_recovery_handler(RecoveryStrategy strategy,
                                                    RecoveryHandler handler) {
  std::lock_guard<std::mutex> lock(error_mutex_);
  recovery_handlers_[strategy] = handler;
}

void ErrorHandlerManager::report_error(const ErrorDetails &error) {
  std::lock_guard<std::mutex> lock(error_mutex_);

  ErrorDetails enhanced_error = error;
  enhanced_error.error_id = generate_error_id(error);
  enhanced_error.timestamp = std::chrono::system_clock::now();

  if (enhanced_error.stack_trace.empty()) {
    enhanced_error.stack_trace = capture_stack_trace();
  }

  total_error_count_++;

  if (error_aggregation_enabled_.load()) {
    aggregate_similar_errors(enhanced_error);
  }

  error_history_.push_back(enhanced_error);
  if (error_history_.size() > max_error_history_) {
    error_history_.erase(error_history_.begin());
  }

  log_error(enhanced_error);
}

void ErrorHandlerManager::report_error(const std::string &component,
                                       const std::string &message,
                                       ErrorCategory category,
                                       ErrorSeverity severity) {
  ErrorDetails error;
  error.component = component;
  error.message = message;
  error.category = category;
  error.severity = severity;
  error.timestamp = std::chrono::system_clock::now();
  error.stack_trace = capture_stack_trace();

  report_error(error);
}

bool ErrorHandlerManager::handle_error(const ErrorDetails &error) {
  report_error(error);

  std::lock_guard<std::mutex> lock(error_mutex_);
  auto it = error_handlers_.find(error.category);
  if (it != error_handlers_.end()) {
    try {
      return it->second(error);
    } catch (const std::exception &e) {
      LOG_ERROR("error_handler", "error handler failed",
                {{"category", error_category_to_string(error.category)},
                 {"handler_error", e.what()}});
      return false;
    }
  }

  LOG_WARNING("error_handler", "no handler found for error category",
              {{"category", error_category_to_string(error.category)}});
  return false;
}

bool ErrorHandlerManager::attempt_recovery(const ErrorDetails &error) {
  if (!error.is_recoverable ||
      error.suggested_recovery == RecoveryStrategy::NONE) {
    return false;
  }

  std::lock_guard<std::mutex> lock(error_mutex_);
  auto it = recovery_handlers_.find(error.suggested_recovery);
  if (it != recovery_handlers_.end()) {
    try {
      bool success = it->second(error);
      LOG_INFO(
          "error_recovery", success ? "recovery successful" : "recovery failed",
          {{"strategy", recovery_strategy_to_string(error.suggested_recovery)},
           {"error_id", error.error_id}});
      return success;
    } catch (const std::exception &e) {
      LOG_ERROR(
          "error_recovery", "recovery handler failed",
          {{"strategy", recovery_strategy_to_string(error.suggested_recovery)},
           {"error", e.what()}});
      return false;
    }
  }

  return false;
}

std::vector<ErrorDetails>
ErrorHandlerManager::get_recent_errors(size_t count) const {
  std::lock_guard<std::mutex> lock(error_mutex_);

  if (error_history_.size() <= count) {
    return error_history_;
  }

  std::vector<ErrorDetails> recent_errors;
  recent_errors.reserve(count);

  auto start_it = error_history_.end() - count;
  recent_errors.insert(recent_errors.end(), start_it, error_history_.end());

  return recent_errors;
}

std::vector<ErrorDetails>
ErrorHandlerManager::get_errors_by_category(ErrorCategory category) const {
  std::lock_guard<std::mutex> lock(error_mutex_);

  std::vector<ErrorDetails> category_errors;
  std::copy_if(error_history_.begin(), error_history_.end(),
               std::back_inserter(category_errors),
               [category](const ErrorDetails &error) {
                 return error.category == category;
               });

  return category_errors;
}

std::vector<ErrorDetails>
ErrorHandlerManager::get_errors_by_severity(ErrorSeverity severity) const {
  std::lock_guard<std::mutex> lock(error_mutex_);

  std::vector<ErrorDetails> severity_errors;
  std::copy_if(error_history_.begin(), error_history_.end(),
               std::back_inserter(severity_errors),
               [severity](const ErrorDetails &error) {
                 return error.severity == severity;
               });

  return severity_errors;
}

void ErrorHandlerManager::clear_error_history() {
  std::lock_guard<std::mutex> lock(error_mutex_);
  error_history_.clear();
  aggregated_errors_.clear();
  total_error_count_ = 0;
}

size_t ErrorHandlerManager::get_error_count() const {
  return total_error_count_.load();
}

size_t
ErrorHandlerManager::get_error_count_by_category(ErrorCategory category) const {
  std::lock_guard<std::mutex> lock(error_mutex_);

  return std::count_if(error_history_.begin(), error_history_.end(),
                       [category](const ErrorDetails &error) {
                         return error.category == category;
                       });
}

void ErrorHandlerManager::set_max_error_history(size_t max_size) {
  std::lock_guard<std::mutex> lock(error_mutex_);
  max_error_history_ = max_size;

  if (error_history_.size() > max_error_history_) {
    error_history_.erase(error_history_.begin(),
                         error_history_.end() - max_error_history_);
  }
}

void ErrorHandlerManager::enable_error_aggregation(bool enable) {
  error_aggregation_enabled_ = enable;
}

std::string
ErrorHandlerManager::error_category_to_string(ErrorCategory category) const {
  switch (category) {
  case ErrorCategory::NETWORK:
    return "NETWORK";
  case ErrorCategory::SECURITY:
    return "SECURITY";
  case ErrorCategory::CONFIGURATION:
    return "CONFIGURATION";
  case ErrorCategory::SEEDING:
    return "SEEDING";
  case ErrorCategory::AUTHENTICATION:
    return "AUTHENTICATION";
  case ErrorCategory::ROUTING:
    return "ROUTING";
  case ErrorCategory::MEMORY:
    return "MEMORY";
  case ErrorCategory::FILESYSTEM:
    return "FILESYSTEM";
  case ErrorCategory::PROTOCOL:
    return "PROTOCOL";
  case ErrorCategory::SYSTEM:
    return "SYSTEM";
  case ErrorCategory::UNKNOWN:
    return "UNKNOWN";
  default:
    return "UNDEFINED";
  }
}

std::string
ErrorHandlerManager::error_severity_to_string(ErrorSeverity severity) const {
  switch (severity) {
  case ErrorSeverity::LOW:
    return "LOW";
  case ErrorSeverity::MEDIUM:
    return "MEDIUM";
  case ErrorSeverity::HIGH:
    return "HIGH";
  case ErrorSeverity::CRITICAL:
    return "CRITICAL";
  default:
    return "UNDEFINED";
  }
}

std::string ErrorHandlerManager::recovery_strategy_to_string(
    RecoveryStrategy strategy) const {
  switch (strategy) {
  case RecoveryStrategy::NONE:
    return "NONE";
  case RecoveryStrategy::RETRY:
    return "RETRY";
  case RecoveryStrategy::RESTART:
    return "RESTART";
  case RecoveryStrategy::FAILOVER:
    return "FAILOVER";
  case RecoveryStrategy::DEGRADE:
    return "DEGRADE";
  case RecoveryStrategy::ABORT:
    return "ABORT";
  default:
    return "UNDEFINED";
  }
}

ErrorCategory ErrorHandlerManager::string_to_error_category(
    const std::string &category) const {
  static const std::unordered_map<std::string, ErrorCategory> category_map = {
      {"NETWORK", ErrorCategory::NETWORK},
      {"SECURITY", ErrorCategory::SECURITY},
      {"CONFIGURATION", ErrorCategory::CONFIGURATION},
      {"SEEDING", ErrorCategory::SEEDING},
      {"AUTHENTICATION", ErrorCategory::AUTHENTICATION},
      {"ROUTING", ErrorCategory::ROUTING},
      {"MEMORY", ErrorCategory::MEMORY},
      {"FILESYSTEM", ErrorCategory::FILESYSTEM},
      {"PROTOCOL", ErrorCategory::PROTOCOL},
      {"SYSTEM", ErrorCategory::SYSTEM},
      {"UNKNOWN", ErrorCategory::UNKNOWN}};

  auto it = category_map.find(category);
  return (it != category_map.end()) ? it->second : ErrorCategory::UNKNOWN;
}

ErrorSeverity ErrorHandlerManager::string_to_error_severity(
    const std::string &severity) const {
  static const std::unordered_map<std::string, ErrorSeverity> severity_map = {
      {"LOW", ErrorSeverity::LOW},
      {"MEDIUM", ErrorSeverity::MEDIUM},
      {"HIGH", ErrorSeverity::HIGH},
      {"CRITICAL", ErrorSeverity::CRITICAL}};

  auto it = severity_map.find(severity);
  return (it != severity_map.end()) ? it->second : ErrorSeverity::MEDIUM;
}

RecoveryStrategy ErrorHandlerManager::string_to_recovery_strategy(
    const std::string &strategy) const {
  static const std::unordered_map<std::string, RecoveryStrategy> strategy_map =
      {{"NONE", RecoveryStrategy::NONE},
       {"RETRY", RecoveryStrategy::RETRY},
       {"RESTART", RecoveryStrategy::RESTART},
       {"FAILOVER", RecoveryStrategy::FAILOVER},
       {"DEGRADE", RecoveryStrategy::DEGRADE},
       {"ABORT", RecoveryStrategy::ABORT}};

  auto it = strategy_map.find(strategy);
  return (it != strategy_map.end()) ? it->second : RecoveryStrategy::NONE;
}

void ErrorHandlerManager::log_error(const ErrorDetails &error) const {
  auto &logger = Logger::instance();

  Logger::LogEntry entry;
  entry.level =
      error.severity == ErrorSeverity::CRITICAL ? Logger::LogLevel::CRITICAL
      : error.severity == ErrorSeverity::HIGH   ? Logger::LogLevel::ERROR
      : error.severity == ErrorSeverity::MEDIUM ? Logger::LogLevel::WARNING
                                                : Logger::LogLevel::INFO;
  entry.component = error.component;
  entry.message = error.message;
  entry.timestamp = std::chrono::steady_clock::now();
  entry.metadata = error.context;
  entry.metadata["error_id"] = error.error_id;
  entry.metadata["category"] = error_category_to_string(error.category);
  entry.metadata["severity"] = error_severity_to_string(error.severity);
  entry.metadata["recoverable"] = error.is_recoverable ? "true" : "false";
  entry.metadata["recovery_strategy"] =
      recovery_strategy_to_string(error.suggested_recovery);

  if (!error.technical_details.empty()) {
    entry.metadata["technical_details"] = error.technical_details;
  }

  if (!error.stack_trace.empty()) {
    entry.metadata["stack_trace"] = error.stack_trace;
  }

  logger.log(entry.level, entry.component, entry.message, entry.metadata);
}

void ErrorHandlerManager::aggregate_similar_errors(const ErrorDetails &error) {
  std::string aggregation_key = error.component + ":" + error.message;
  aggregated_errors_[aggregation_key].push_back(error);

  if (aggregated_errors_[aggregation_key].size() > 100) {
    aggregated_errors_[aggregation_key].erase(
        aggregated_errors_[aggregation_key].begin());
  }
}

bool ErrorHandlerManager::is_similar_error(const ErrorDetails &error1,
                                           const ErrorDetails &error2) const {
  return error1.component == error2.component &&
         error1.category == error2.category && error1.message == error2.message;
}

std::string
ErrorHandlerManager::generate_error_id(const ErrorDetails &error) const {
  auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                       error.timestamp.time_since_epoch())
                       .count();

  std::hash<std::string> hasher;
  size_t hash =
      hasher(error.component + error.message + std::to_string(timestamp));

  std::ostringstream oss;
  oss << "ERR_" << std::hex << hash;
  return oss.str();
}

std::string ErrorHandlerManager::capture_stack_trace() const {
  const int max_frames = 64;
  void *frames[max_frames];

  int frame_count = backtrace(frames, max_frames);
  char **symbols = backtrace_symbols(frames, frame_count);

  if (!symbols) {
    return "stack trace unavailable";
  }

  std::ostringstream trace;
  for (int i = 0; i < frame_count; ++i) {
    std::string frame_info = symbols[i];

    size_t begin = frame_info.find('(');
    size_t end = frame_info.find('+');

    if (begin != std::string::npos && end != std::string::npos && begin < end) {
      std::string mangled_name = frame_info.substr(begin + 1, end - begin - 1);

      int status;
      char *demangled =
          abi::__cxa_demangle(mangled_name.c_str(), nullptr, nullptr, &status);

      if (status == 0 && demangled) {
        trace << "  " << i << ": " << demangled << "\n";
        free(demangled);
      } else {
        trace << "  " << i << ": " << mangled_name << "\n";
      }
    } else {
      trace << "  " << i << ": " << frame_info << "\n";
    }
  }

  free(symbols);
  return trace.str();
}

} // namespace CipherProxy::Infrastructure
