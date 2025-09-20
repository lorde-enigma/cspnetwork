#include "testing/test_framework.h"
#include <iostream>

using namespace seeded_vpn::testing;

int main() {
    auto& runner = TestRunner::instance();
    
    std::cout << "=== Seeded VPN Server Test Suite ===" << std::endl;
    std::cout << "Running comprehensive tests..." << std::endl << std::endl;
    
    runner.set_parallel_execution(true);
    runner.set_output_format("console");
    
    auto all_results = runner.run_all_tests();
    
    std::cout << std::endl << "=== Test Execution Complete ===" << std::endl;
    
    runner.export_xml_report(all_results, "test_results.xml");
    runner.export_json_report(all_results, "test_results.json");
    
    std::cout << "Detailed reports exported to:" << std::endl;
    std::cout << "- test_results.xml" << std::endl;
    std::cout << "- test_results.json" << std::endl;
    
    int passed = 0, failed = 0, errors = 0;
    for (const auto& result : all_results) {
        switch (result.status) {
            case TestStatus::PASSED:
                passed++;
                break;
            case TestStatus::FAILED:
                failed++;
                break;
            case TestStatus::ERROR:
                errors++;
                break;
            default:
                break;
        }
    }
    
    if (failed > 0 || errors > 0) {
        std::cout << std::endl << "❌ Tests failed - " << failed << " failures, " 
                  << errors << " errors" << std::endl;
        return 1;
    } else {
        std::cout << std::endl << "✅ All tests passed - " << passed 
                  << " tests successful" << std::endl;
        return 0;
    }
}
