cmake_minimum_required(VERSION 3.20)
project(cspnetwork VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -O3 -march=native")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(YAMLCPP REQUIRED yaml-cpp)

include_directories(include)

file(GLOB_RECURSE DOMAIN_SOURCES "src/domain/*.cpp")
file(GLOB_RECURSE APPLICATION_SOURCES "src/application/*.cpp")
file(GLOB_RECURSE INFRASTRUCTURE_SOURCES "src/infrastructure/*.cpp")
file(GLOB_RECURSE PRESENTATION_SOURCES "src/presentation/*.cpp")

set(VPN_SOURCES
    ${DOMAIN_SOURCES}
    ${APPLICATION_SOURCES}
    ${INFRASTRUCTURE_SOURCES}
    ${PRESENTATION_SOURCES}
)

set(CLIENT_SOURCES
    ${DOMAIN_SOURCES}
    ${INFRASTRUCTURE_SOURCES}
    src/application/services.cpp
    src/application/cspnetwork_client.cpp
)

add_executable(cspnetwork
    src/main.cpp
    src/application/services.cpp
    src/application/cspnetwork_client.cpp
    src/infrastructure/config_manager.cpp
    src/infrastructure/error_handler.cpp
    src/infrastructure/tun_interface.cpp
    src/infrastructure/async_socket_manager.cpp
    src/infrastructure/cache_manager.cpp
    src/infrastructure/monitoring_system.cpp
    src/infrastructure/packet_processing_pipeline.cpp
    src/infrastructure/repositories.cpp
    src/infrastructure/security.cpp
    src/infrastructure/seeded_router.cpp
    src/infrastructure/thread_management.cpp
    src/infrastructure/cspnetwork_protocol.cpp
    src/infrastructure/ipv6_address_manager.cpp
    src/infrastructure/ip_pool.cpp
    src/infrastructure/crc32.cpp
    src/presentation/server.cpp
    src/presentation/cli.cpp
    src/presentation/container.cpp
    src/presentation/factory.cpp
    src/presentation/udp_tunnel_server.cpp
    src/protocol/udp_tunnel_protocol.cpp
    src/protocol/tunnel_packet.cpp
    src/domain/entities.cpp
    src/domain/connection_context.cpp
    src/domain/cspnetwork_config.cpp
)

add_executable(cspvpn-client
    src/client_main.cpp
    src/application/cspnetwork_client.cpp
    src/infrastructure/tun_interface.cpp
    src/domain/entities.cpp
)

add_executable(cspvpn-gen
    src/generator_main.cpp
    src/application/client_generator.cpp
    src/infrastructure/config_manager.cpp
    src/infrastructure/monitoring_system.cpp
    src/infrastructure/repositories.cpp
    src/infrastructure/seed_generator.cpp
    src/infrastructure/ipv6_address_manager.cpp
    src/infrastructure/ipv6_seeded_generator.cpp
    src/infrastructure/seeded_connection_manager.cpp
    src/infrastructure/seeded_system_monitor.cpp
    src/infrastructure/connection_seeder.cpp
    src/domain/entities.cpp
)

file(GLOB_RECURSE TEST_FRAMEWORK_SOURCES "src/testing/*.cpp")
file(GLOB_RECURSE UNIT_TEST_SOURCES "tests/unit/*.cpp")
file(GLOB_RECURSE INTEGRATION_TEST_SOURCES "tests/integration/*.cpp")
file(GLOB_RECURSE PERFORMANCE_TEST_SOURCES "tests/performance/*.cpp")

set(TEST_SOURCES
    ${TEST_FRAMEWORK_SOURCES}
    ${UNIT_TEST_SOURCES}
    ${INTEGRATION_TEST_SOURCES}
    ${PERFORMANCE_TEST_SOURCES}
)

# Test executable
add_executable(cspnetwork-tests tests/test_main.cpp)
target_include_directories(cspnetwork-tests PRIVATE include)
target_link_libraries(cspnetwork-tests
    Threads::Threads
    ${YAMLCPP_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    dl
)

# Client Test Executable
add_executable(cspvpn-client-test 
    mindvoices/client_test.cpp
    src/protocol/udp_tunnel_protocol.cpp
    src/protocol/tunnel_packet.cpp
    src/infrastructure/crc32.cpp
)
target_include_directories(cspvpn-client-test PRIVATE include)
target_link_libraries(cspvpn-client-test
    Threads::Threads
    ${YAMLCPP_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    dl
)

# CSP Network Client Core - removed (no main function needed)

target_link_libraries(cspnetwork
    Threads::Threads
    ${YAMLCPP_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    dl
)

target_link_libraries(cspvpn-client
    Threads::Threads
    ${YAMLCPP_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    dl
)

target_link_libraries(cspvpn-gen
    Threads::Threads
    ${YAMLCPP_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    dl
)

# target_link_libraries(cspnetwork-tests
#     Threads::Threads
#     ${YAMLCPP_LIBRARIES}
#     OpenSSL::SSL
#     OpenSSL::Crypto
#     dl
# )

target_include_directories(cspnetwork PRIVATE ${YAMLCPP_INCLUDE_DIRS})
target_include_directories(cspvpn-client PRIVATE ${YAMLCPP_INCLUDE_DIRS})
target_include_directories(cspvpn-gen PRIVATE ${YAMLCPP_INCLUDE_DIRS})
# target_include_directories(cspnetwork-tests PRIVATE ${YAMLCPP_INCLUDE_DIRS})

target_compile_options(cspnetwork PRIVATE ${YAMLCPP_CFLAGS_OTHER})
target_compile_options(cspvpn-client PRIVATE ${YAMLCPP_CFLAGS_OTHER})
target_compile_options(cspvpn-gen PRIVATE ${YAMLCPP_CFLAGS_OTHER})
# target_compile_options(cspnetwork-tests PRIVATE ${YAMLCPP_CFLAGS_OTHER})

set_target_properties(cspnetwork PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_target_properties(cspvpn-client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_target_properties(cspvpn-gen PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# set_target_properties(cspnetwork-tests PROPERTIES
#     RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
# )

set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Installation prefix")

install(TARGETS cspnetwork cspvpn-client cspvpn-gen
    RUNTIME DESTINATION bin
    COMPONENT Runtime
)

install(FILES config/default.yaml
    DESTINATION etc/cspnetwork
    RENAME config.yaml
    COMPONENT Config
)

install(FILES 
    config/client.cspvpn
    config/client.yaml
    DESTINATION etc/cspnetwork/examples
    COMPONENT Config
)

install(FILES services/cspnetwork.service
    DESTINATION /etc/systemd/system
    COMPONENT SystemD
)

install(PROGRAMS 
    scripts/install.sh
    scripts/uninstall.sh
    scripts/build.sh
    scripts/deploy.sh
    DESTINATION share/cspnetwork/scripts
    COMPONENT Scripts
)

install(CODE "
    file(MAKE_DIRECTORY \"\$ENV{DESTDIR}/var/log/cspnetwork\")
    file(MAKE_DIRECTORY \"\$ENV{DESTDIR}/var/lib/cspnetwork\")
    file(MAKE_DIRECTORY \"\$ENV{DESTDIR}/etc/cspnetwork\")
    
    execute_process(
        COMMAND getent group cspnetwork
        RESULT_VARIABLE GROUP_EXISTS
        OUTPUT_QUIET ERROR_QUIET
    )
    if(NOT GROUP_EXISTS EQUAL 0)
        execute_process(COMMAND groupadd -r cspnetwork)
    endif()
    
    execute_process(
        COMMAND getent passwd cspnetwork
        RESULT_VARIABLE USER_EXISTS
        OUTPUT_QUIET ERROR_QUIET
    )
    if(NOT USER_EXISTS EQUAL 0)
        execute_process(
            COMMAND useradd -r -g cspnetwork -d /var/lib/cspnetwork -s /bin/false cspnetwork
        )
    endif()
    
    execute_process(COMMAND chown -R cspnetwork:cspnetwork /var/log/cspnetwork)
    execute_process(COMMAND chown -R cspnetwork:cspnetwork /var/lib/cspnetwork)
    execute_process(COMMAND chown -R cspnetwork:cspnetwork /etc/cspnetwork)
    execute_process(COMMAND chmod 755 /var/log/cspnetwork)
    execute_process(COMMAND chmod 755 /var/lib/cspnetwork)
    execute_process(COMMAND chmod 755 /etc/cspnetwork)
    execute_process(COMMAND chmod 640 /etc/cspnetwork/config.yaml)
    
    execute_process(COMMAND systemctl daemon-reload)
    execute_process(COMMAND systemctl enable cspnetwork.service)
    
    message(STATUS \"Installation completed successfully\")
    message(STATUS \"Service installed: cspnetwork.service\")
    message(STATUS \"Configuration: /etc/cspnetwork/config.yaml\")
    message(STATUS \"Logs: /var/log/cspnetwork/\")
    message(STATUS \"To start the service: systemctl start cspnetwork\")
")

add_custom_target(uninstall
    COMMAND systemctl stop cspnetwork.service || true
    COMMAND systemctl disable cspnetwork.service || true
    COMMAND rm -f /etc/systemd/system/cspnetwork.service
    COMMAND rm -f /usr/local/bin/cspnetwork
    COMMAND rm -f /usr/local/bin/cspvpn-client
    COMMAND rm -rf /etc/cspnetwork
    COMMAND rm -rf /usr/local/share/cspnetwork
    COMMAND systemctl daemon-reload || true
    COMMAND userdel cspnetwork || true
    COMMAND groupdel cspnetwork || true
    COMMENT "Uninstalling CSP Network VPN"
)

# add_custom_target(run-tests
#     COMMAND cspnetwork-tests
#     DEPENDS cspnetwork-tests
#     COMMENT "Running all tests"
# )

# add_custom_target(run-unit-tests
#     COMMAND cspnetwork-tests --tag unit
#     DEPENDS cspnetwork-tests
#     COMMENT "Running unit tests"
# )

# add_custom_target(run-integration-tests
#     COMMAND cspnetwork-tests --tag integration
#     DEPENDS cspnetwork-tests
#     COMMENT "Running integration tests"
# )

# add_custom_target(run-performance-tests
#     COMMAND cspnetwork-tests --tag performance
#     DEPENDS cspnetwork-tests
#     COMMENT "Running performance tests"
# )
