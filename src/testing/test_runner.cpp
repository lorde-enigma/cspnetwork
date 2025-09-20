#include "testing/test_framework.h"
#include <algorithm>
#include <execution>
#include <iostream>
#include <fstream>
#include <future>
#include <sstream>
#include <chrono>

namespace seeded_vpn::testing {

TestRunner& TestRunner::instance() {
    static TestRunner instance;
    return instance;
}

void TestRunner::register_suite(const TestSuite& suite) {
    test_suites_[suite.name] = suite;
}

std::vector<TestResult> TestRunner::run_all_tests() {
    std::vector<TestResult> all_results;
    
    for (const auto& [suite_name, suite] : test_suites_) {
        auto suite_results = run_suite(suite_name);
        all_results.insert(all_results.end(), suite_results.begin(), suite_results.end());
        
        if (stop_on_failure_) {
            bool has_failure = std::any_of(suite_results.begin(), suite_results.end(),
                [](const TestResult& result) {
                    return result.status == TestStatus::FAILED || result.status == TestStatus::ERROR;
                });
            if (has_failure) break;
        }
    }
    
    generate_report(all_results);
    return all_results;
}

std::vector<TestResult> TestRunner::run_suite(const std::string& suite_name) {
    auto it = test_suites_.find(suite_name);
    if (it == test_suites_.end()) {
        TestResult error_result;
        error_result.suite_name = suite_name;
        error_result.test_name = "SUITE_NOT_FOUND";
        error_result.status = TestStatus::ERROR;
        error_result.error_message = "Test suite not found: " + suite_name;
        return {error_result};
    }
    
    const TestSuite& suite = it->second;
    std::vector<TestResult> results;
    
    try {
        if (suite.setup_function) {
            suite.setup_function();
        }
        
        if (parallel_execution_) {
            std::vector<std::future<TestResult>> futures;
            for (const auto& test : suite.tests) {
                futures.push_back(std::async(std::launch::async, 
                    [this, &suite, &test]() {
                        return run_single_test(suite, test);
                    }));
            }
            
            for (auto& future : futures) {
                results.push_back(future.get());
            }
        } else {
            for (const auto& test : suite.tests) {
                auto result = run_single_test(suite, test);
                results.push_back(result);
                
                if (stop_on_failure_ && 
                    (result.status == TestStatus::FAILED || result.status == TestStatus::ERROR)) {
                    break;
                }
            }
        }
        
        if (suite.teardown_function) {
            suite.teardown_function();
        }
    }
    catch (const std::exception& e) {
        TestResult suite_error;
        suite_error.suite_name = suite_name;
        suite_error.test_name = "SUITE_ERROR";
        suite_error.status = TestStatus::ERROR;
        suite_error.error_message = "Suite execution error: " + std::string(e.what());
        results.push_back(suite_error);
    }
    
    return results;
}

TestResult TestRunner::run_test(const std::string& suite_name, const std::string& test_name) {
    auto suite_it = test_suites_.find(suite_name);
    if (suite_it == test_suites_.end()) {
        TestResult error_result;
        error_result.suite_name = suite_name;
        error_result.test_name = test_name;
        error_result.status = TestStatus::ERROR;
        error_result.error_message = "Test suite not found: " + suite_name;
        return error_result;
    }
    
    const TestSuite& suite = suite_it->second;
    auto test_it = std::find_if(suite.tests.begin(), suite.tests.end(),
        [&test_name](const TestCase& test) { return test.name == test_name; });
    
    if (test_it == suite.tests.end()) {
        TestResult error_result;
        error_result.suite_name = suite_name;
        error_result.test_name = test_name;
        error_result.status = TestStatus::ERROR;
        error_result.error_message = "Test not found: " + test_name;
        return error_result;
    }
    
    return run_single_test(suite, *test_it);
}

std::vector<TestResult> TestRunner::run_tests_by_tag(const std::string& tag) {
    std::vector<TestResult> results;
    
    for (const auto& [suite_name, suite] : test_suites_) {
        for (const auto& test : suite.tests) {
            auto tag_it = std::find(test.tags.begin(), test.tags.end(), tag);
            if (tag_it != test.tags.end()) {
                auto result = run_single_test(suite, test);
                results.push_back(result);
                
                if (stop_on_failure_ && 
                    (result.status == TestStatus::FAILED || result.status == TestStatus::ERROR)) {
                    return results;
                }
            }
        }
    }
    
    return results;
}

TestResult TestRunner::run_single_test(const TestSuite& suite, const TestCase& test) {
    TestResult result;
    result.suite_name = suite.name;
    result.test_name = test.name;
    result.timestamp = std::chrono::system_clock::now();
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        auto test_future = std::async(std::launch::async, test.test_function);
        auto status = test_future.wait_for(test.timeout);
        
        if (status == std::future_status::timeout) {
            result.status = TestStatus::ERROR;
            result.error_message = "Test timeout after " + std::to_string(test.timeout.count()) + "ms";
        } else {
            test_future.get();
            result.status = TestStatus::PASSED;
        }
    }
    catch (const AssertionException& e) {
        result.status = TestStatus::FAILED;
        result.error_message = e.what();
    }
    catch (const std::exception& e) {
        result.status = TestStatus::ERROR;
        result.error_message = "Unexpected error: " + std::string(e.what());
    }
    catch (...) {
        result.status = TestStatus::ERROR;
        result.error_message = "Unknown error occurred";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    result.execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    return result;
}

void TestRunner::generate_report(const std::vector<TestResult>& results, std::ostream& output) {
    if (output_format_ == "json") {
        generate_json_report(results, output);
    } else if (output_format_ == "xml") {
        generate_xml_report(results, output);
    } else {
        generate_console_report(results, output);
    }
}

void TestRunner::generate_console_report(const std::vector<TestResult>& results, std::ostream& output) {
    int passed = 0, failed = 0, skipped = 0, errors = 0;
    
    output << "\n=== Test Results ===\n";
    
    for (const auto& result : results) {
        switch (result.status) {
            case TestStatus::PASSED:
                output << "[PASS] ";
                passed++;
                break;
            case TestStatus::FAILED:
                output << "[FAIL] ";
                failed++;
                break;
            case TestStatus::SKIPPED:
                output << "[SKIP] ";
                skipped++;
                break;
            case TestStatus::ERROR:
                output << "[ERROR] ";
                errors++;
                break;
        }
        
        output << result.suite_name << "::" << result.test_name 
               << " (" << result.execution_time.count() << "ms)";
        
        if (!result.error_message.empty()) {
            output << "\n        " << result.error_message;
        }
        output << "\n";
    }
    
    output << "\n=== Summary ===\n";
    output << "Total: " << results.size() << "\n";
    output << "Passed: " << passed << "\n";
    output << "Failed: " << failed << "\n";
    output << "Skipped: " << skipped << "\n";
    output << "Errors: " << errors << "\n";
    
    double success_rate = results.empty() ? 0.0 : (double)passed / results.size() * 100.0;
    output << "Success Rate: " << std::fixed << std::setprecision(1) << success_rate << "%\n";
}

void TestRunner::generate_json_report(const std::vector<TestResult>& results, std::ostream& output) {
    output << "{\n";
    output << "  \"test_results\": [\n";
    
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& result = results[i];
        output << "    {\n";
        output << "      \"suite\": \"" << result.suite_name << "\",\n";
        output << "      \"test\": \"" << result.test_name << "\",\n";
        output << "      \"status\": \"" << status_to_string(result.status) << "\",\n";
        output << "      \"execution_time_ms\": " << result.execution_time.count() << ",\n";
        output << "      \"error_message\": \"" << escape_json(result.error_message) << "\",\n";
        
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            result.timestamp.time_since_epoch()).count();
        output << "      \"timestamp\": " << timestamp << "\n";
        
        output << "    }";
        if (i < results.size() - 1) output << ",";
        output << "\n";
    }
    
    output << "  ],\n";
    
    int passed = 0, failed = 0, skipped = 0, errors = 0;
    for (const auto& result : results) {
        switch (result.status) {
            case TestStatus::PASSED: passed++; break;
            case TestStatus::FAILED: failed++; break;
            case TestStatus::SKIPPED: skipped++; break;
            case TestStatus::ERROR: errors++; break;
        }
    }
    
    output << "  \"summary\": {\n";
    output << "    \"total\": " << results.size() << ",\n";
    output << "    \"passed\": " << passed << ",\n";
    output << "    \"failed\": " << failed << ",\n";
    output << "    \"skipped\": " << skipped << ",\n";
    output << "    \"errors\": " << errors << ",\n";
    
    double success_rate = results.empty() ? 0.0 : (double)passed / results.size() * 100.0;
    output << "    \"success_rate\": " << std::fixed << std::setprecision(1) << success_rate << "\n";
    output << "  }\n";
    output << "}\n";
}

void TestRunner::generate_xml_report(const std::vector<TestResult>& results, std::ostream& output) {
    output << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    output << "<testsuites>\n";
    
    std::map<std::string, std::vector<TestResult>> suites;
    for (const auto& result : results) {
        suites[result.suite_name].push_back(result);
    }
    
    for (const auto& [suite_name, suite_results] : suites) {
        int passed = 0, failed = 0, skipped = 0, errors = 0;
        for (const auto& result : suite_results) {
            switch (result.status) {
                case TestStatus::PASSED: passed++; break;
                case TestStatus::FAILED: failed++; break;
                case TestStatus::SKIPPED: skipped++; break;
                case TestStatus::ERROR: errors++; break;
            }
        }
        
        output << "  <testsuite name=\"" << escape_xml(suite_name) << "\" tests=\"" 
               << suite_results.size() << "\" failures=\"" << failed 
               << "\" errors=\"" << errors << "\" skipped=\"" << skipped << "\">\n";
        
        for (const auto& result : suite_results) {
            output << "    <testcase name=\"" << escape_xml(result.test_name) 
                   << "\" time=\"" << (result.execution_time.count() / 1000.0) << "\"";
            
            if (result.status == TestStatus::PASSED) {
                output << "/>\n";
            } else {
                output << ">\n";
                
                if (result.status == TestStatus::FAILED) {
                    output << "      <failure message=\"" << escape_xml(result.error_message) 
                           << "\"></failure>\n";
                } else if (result.status == TestStatus::ERROR) {
                    output << "      <error message=\"" << escape_xml(result.error_message) 
                           << "\"></error>\n";
                } else if (result.status == TestStatus::SKIPPED) {
                    output << "      <skipped/>\n";
                }
                
                output << "    </testcase>\n";
            }
        }
        
        output << "  </testsuite>\n";
    }
    
    output << "</testsuites>\n";
}

void TestRunner::export_xml_report(const std::vector<TestResult>& results, const std::string& filename) {
    std::ofstream file(filename);
    if (file.is_open()) {
        generate_xml_report(results, file);
        file.close();
    }
}

void TestRunner::export_json_report(const std::vector<TestResult>& results, const std::string& filename) {
    std::ofstream file(filename);
    if (file.is_open()) {
        generate_json_report(results, file);
        file.close();
    }
}

std::string TestRunner::status_to_string(TestStatus status) {
    switch (status) {
        case TestStatus::PASSED: return "PASSED";
        case TestStatus::FAILED: return "FAILED";
        case TestStatus::SKIPPED: return "SKIPPED";
        case TestStatus::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

std::string TestRunner::escape_json(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped += c; break;
        }
    }
    return escaped;
}

std::string TestRunner::escape_xml(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '&': escaped += "&amp;"; break;
            case '"': escaped += "&quot;"; break;
            case '\'': escaped += "&apos;"; break;
            default: escaped += c; break;
        }
    }
    return escaped;
}

}
