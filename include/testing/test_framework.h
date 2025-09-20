#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <numeric>
#include <future>
#include <execution>
#include <set>
#include <map>

namespace seeded_vpn::testing {

enum class TestStatus {
    PASSED,
    FAILED,
    SKIPPED,
    ERROR
};

struct TestCase {
    std::string name;
    std::string description;
    std::function<void()> test_function;
    std::vector<std::string> tags;
    std::chrono::milliseconds timeout{std::chrono::milliseconds(5000)};
    
    TestCase(const std::string& test_name, const std::function<void()>& func, 
             const std::string& desc = "", const std::vector<std::string>& test_tags = {})
        : name(test_name), description(desc), test_function(func), tags(test_tags) {}
};

struct TestSuite {
    std::string name;
    std::vector<TestCase> tests;
    std::function<void()> setup_function;
    std::function<void()> teardown_function;
    
    TestSuite(const std::string& suite_name) : name(suite_name) {}
    
    void add_test(const TestCase& test) {
        tests.push_back(test);
    }
    
    void set_setup(const std::function<void()>& setup) {
        setup_function = setup;
    }
    
    void set_teardown(const std::function<void()>& teardown) {
        teardown_function = teardown;
    }
};

struct TestResult {
    std::string test_name;
    std::string suite_name;
    TestStatus status;
    std::string error_message;
    std::chrono::milliseconds execution_time;
    std::chrono::system_clock::time_point timestamp;
    
    TestResult() : status(TestStatus::FAILED), execution_time(0), 
                  timestamp(std::chrono::system_clock::now()) {}
};

class TestRunner {
public:
    static TestRunner& instance();
    
    void register_suite(const TestSuite& suite);
    std::vector<TestResult> run_all_tests();
    void run_suite(const std::string& suite_name);
    void run_test(const std::string& suite_name, const std::string& test_name);
    void run_tests_by_tag(const std::string& tag);
    
    std::vector<TestResult> get_results() const;
    void clear_results();
    
    void set_output_format(const std::string& format);
    void set_output_file(const std::string& filename);
    void enable_parallel_execution(bool enable);
    void set_parallel_execution(bool enable) { enable_parallel_execution(enable); }
    void set_max_parallel_tests(size_t max_tests);
    
    void print_summary() const;
    void export_xml_report(const std::vector<TestResult>&, const std::string& filename) const;
    void export_json_report(const std::vector<TestResult>&, const std::string& filename) const;
    void export_results_xml(const std::string& filename) const;
    void export_results_json(const std::string& filename) const;

private:
    TestRunner() = default;
    
    TestResult run_single_test(const TestCase& test, const std::string& suite_name);
    void execute_setup(const std::function<void()>& setup);
    void execute_teardown(const std::function<void()>& teardown);
    
    std::vector<TestSuite> test_suites_;
    std::vector<TestResult> test_results_;
    std::string output_format_{"console"};
    std::string output_file_;
    bool parallel_execution_{false};
    size_t max_parallel_tests_{4};
};

class Assertion {
public:
    template<typename T>
    static void assert_equal(const T& expected, const T& actual, const std::string& message = "") {
        if (expected != actual) {
            throw_assertion_error("assertion_equal", expected, actual, message);
        }
    }
    
    template<typename T>
    static void assert_not_equal(const T& expected, const T& actual, const std::string& message = "") {
        if (expected == actual) {
            throw_assertion_error("assertion_not_equal", expected, actual, message);
        }
    }
    
    static void assert_true(bool condition, const std::string& message = "") {
        if (!condition) {
            throw_assertion_error("assertion_true", true, false, message);
        }
    }
    
    static void assert_false(bool condition, const std::string& message = "") {
        if (condition) {
            throw_assertion_error("assertion_false", false, true, message);
        }
    }
    
    static void assert_null(const void* ptr, const std::string& message = "") {
        if (ptr != nullptr) {
            throw_assertion_error("assertion_null", "nullptr", "non-null", message);
        }
    }
    
    static void assert_not_null(const void* ptr, const std::string& message = "") {
        if (ptr == nullptr) {
            throw_assertion_error("assertion_not_null", "non-null", "nullptr", message);
        }
    }
    
    template<typename T>
    static void assert_greater(const T& value, const T& threshold, const std::string& message = "") {
        if (!(value > threshold)) {
            throw_assertion_error("assertion_greater", 
                                std::string("value > ") + std::to_string(threshold),
                                std::string("value = ") + std::to_string(value), message);
        }
    }
    
    template<typename T>
    static void assert_less(const T& value, const T& threshold, const std::string& message = "") {
        if (!(value < threshold)) {
            throw_assertion_error("assertion_less", 
                                std::string("value < ") + std::to_string(threshold),
                                std::string("value = ") + std::to_string(value), message);
        }
    }
    
    template<typename Exception>
    static void assert_throws(const std::function<void()>& func, const std::string& message = "") {
        bool exception_thrown = false;
        try {
            func();
        } catch (const Exception&) {
            exception_thrown = true;
        } catch (...) {
            throw_assertion_error("assertion_throws", "specific exception", "different exception", message);
        }
        
        if (!exception_thrown) {
            throw_assertion_error("assertion_throws", "exception", "no exception", message);
        }
    }
    
    static void assert_no_throw(const std::function<void()>& func, const std::string& message = "") {
        try {
            func();
        } catch (...) {
            throw_assertion_error("assertion_no_throw", "no exception", "exception thrown", message);
        }
    }

private:
    template<typename T1, typename T2>
    static void throw_assertion_error(const std::string& assertion_type,
                                     const T1& expected, const T2& actual,
                                     const std::string& message) {
        std::string error_msg = assertion_type + " failed";
        if (!message.empty()) {
            error_msg += ": " + message;
        }
        error_msg += " (expected vs actual mismatch)";
        throw std::runtime_error(error_msg);
    }
};

class MockObject {
public:
    struct MethodCall {
        std::string method_name;
        std::vector<std::string> arguments;
        std::chrono::system_clock::time_point timestamp;
        
        MethodCall(const std::string& name, const std::vector<std::string>& args = {})
            : method_name(name), arguments(args), timestamp(std::chrono::system_clock::now()) {}
    };
    
    void record_call(const std::string& method_name, const std::vector<std::string>& args = {}) {
        method_calls_.emplace_back(method_name, args);
    }
    
    size_t get_call_count(const std::string& method_name) const {
        return std::count_if(method_calls_.begin(), method_calls_.end(),
                           [&method_name](const MethodCall& call) {
                               return call.method_name == method_name;
                           });
    }
    
    bool was_called(const std::string& method_name) const {
        return get_call_count(method_name) > 0;
    }
    
    std::vector<MethodCall> get_calls() const {
        return method_calls_;
    }
    
    void clear_calls() {
        method_calls_.clear();
    }

private:
    std::vector<MethodCall> method_calls_;
};

class TestFixture {
public:
    virtual ~TestFixture() = default;
    virtual void setup() {}
    virtual void teardown() {}
};

template<typename T>
class ParameterizedTest {
public:
    using TestFunction = std::function<void(const T&)>;
    
    ParameterizedTest(const std::string& name, TestFunction func)
        : test_name_(name), test_function_(func) {}
    
    void add_parameter(const T& param) {
        parameters_.push_back(param);
    }
    
    std::vector<TestCase> generate_test_cases() const {
        std::vector<TestCase> test_cases;
        
        for (size_t i = 0; i < parameters_.size(); ++i) {
            std::string case_name = test_name_ + "_param_" + std::to_string(i);
            TestCase test_case(case_name, [this, i]() {
                test_function_(parameters_[i]);
            });
            test_cases.push_back(test_case);
        }
        
        return test_cases;
    }

private:
    std::string test_name_;
    TestFunction test_function_;
    std::vector<T> parameters_;
};

class BenchmarkTest {
public:
    struct BenchmarkResult {
        std::string test_name;
        size_t iterations;
        std::chrono::nanoseconds total_time;
        std::chrono::nanoseconds average_time;
        std::chrono::nanoseconds min_time;
        std::chrono::nanoseconds max_time;
        double operations_per_second;
    };
    
    static BenchmarkResult run_benchmark(const std::string& name,
                                        const std::function<void()>& func,
                                        size_t iterations = 1000) {
        BenchmarkResult result;
        result.test_name = name;
        result.iterations = iterations;
        result.min_time = std::chrono::nanoseconds::max();
        result.max_time = std::chrono::nanoseconds::zero();
        
        auto start_total = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            func();
            auto end = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
            result.min_time = std::min(result.min_time, duration);
            result.max_time = std::max(result.max_time, duration);
        }
        
        auto end_total = std::chrono::high_resolution_clock::now();
        result.total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_total - start_total);
        result.average_time = result.total_time / iterations;
        result.operations_per_second = 1e9 / result.average_time.count();
        
        return result;
    }
};

#define TEST_SUITE(name) \
    TestSuite create_##name##_suite() { \
        TestSuite suite(#name);

#define TEST_CASE(name, description) \
    suite.add_test(TestCase(#name, []() {

#define END_TEST_CASE \
    }, description));

#define END_TEST_SUITE \
    return suite; \
    }

#define SETUP() \
    suite.set_setup([]() {

#define TEARDOWN() \
    suite.set_teardown([]() {

#define END_SETUP_TEARDOWN \
    });

#define ASSERT_EQ(expected, actual) \
    Assertion::assert_equal(expected, actual, #expected " == " #actual)

#define ASSERT_NE(expected, actual) \
    Assertion::assert_not_equal(expected, actual, #expected " != " #actual)

#define ASSERT_TRUE(condition) \
    Assertion::assert_true(condition, #condition " is true")

#define ASSERT_FALSE(condition) \
    Assertion::assert_false(condition, #condition " is false")

#define ASSERT_NULL(ptr) \
    Assertion::assert_null(ptr, #ptr " is null")

#define ASSERT_NOT_NULL(ptr) \
    Assertion::assert_not_null(ptr, #ptr " is not null")

#define ASSERT_GT(value, threshold) \
    Assertion::assert_greater(value, threshold, #value " > " #threshold)

#define ASSERT_LT(value, threshold) \
    Assertion::assert_less(value, threshold, #value " < " #threshold)

#define ASSERT_THROWS(exception_type, func) \
    Assertion::assert_throws<exception_type>(func, #func " throws " #exception_type)

#define ASSERT_NO_THROW(func) \
    Assertion::assert_no_throw(func, #func " does not throw")

}
