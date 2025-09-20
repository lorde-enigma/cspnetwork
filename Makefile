BUILD_TYPE ?= Release
BUILD_DIR = build
CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

.PHONY: all clean build test install uninstall help
.PHONY: service-start service-stop service-restart service-status service-logs
.PHONY: dev-build dev-install dev-clean format lint

all: build

build:
	@echo "building csp network vpn..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake $(CMAKE_FLAGS) .. && make -j$$(nproc)
	@echo "build completed successfully"

clean:
	@echo "cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@echo "clean completed"

rebuild: clean build

test: build
	@echo "running tests..."
	@cd $(BUILD_DIR) && make run-tests
	@echo "tests completed"

test-unit: build
	@echo "running unit tests..."
	@cd $(BUILD_DIR) && make run-unit-tests

test-integration: build
	@echo "running integration tests..."
	@cd $(BUILD_DIR) && make run-integration-tests

test-performance: build
	@echo "running performance tests..."
	@cd $(BUILD_DIR) && make run-performance-tests

install: build
	@echo "installing csp network vpn system-wide..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "error: installation requires root privileges. use 'sudo make install'"; \
		exit 1; \
	fi
	@cd $(BUILD_DIR) && make install
	@echo "installation completed successfully"
	@echo "service: cspnetwork.service"
	@echo "config:  /etc/cspnetwork/config.yaml"
	@echo "logs:    /var/log/cspnetwork/"
	@echo "start:   systemctl start cspnetwork"

uninstall:
	@echo "uninstalling csp network vpn..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "error: uninstallation requires root privileges. use 'sudo make uninstall'"; \
		exit 1; \
	fi
	@if [ -d "$(BUILD_DIR)" ]; then \
		cd $(BUILD_DIR) && make uninstall; \
	else \
		echo "performing manual cleanup..."; \
		systemctl stop cspnetwork.service 2>/dev/null || true; \
		systemctl disable cspnetwork.service 2>/dev/null || true; \
		rm -f /etc/systemd/system/cspnetwork.service; \
		rm -f /usr/local/bin/cspnetwork; \
		rm -rf /etc/cspnetwork; \
		rm -rf /usr/local/share/cspnetwork; \
		systemctl daemon-reload 2>/dev/null || true; \
		userdel cspnetwork 2>/dev/null || true; \
		groupdel cspnetwork 2>/dev/null || true; \
	fi
	@echo "uninstallation completed"

dev-build:
	@echo "building for development..."
	@BUILD_TYPE=Debug $(MAKE) build

dev-install: dev-build
	@echo "installing development version..."
	@sudo $(MAKE) install

dev-clean:
	@echo "cleaning development environment..."
	@$(MAKE) clean

service-start:
	@echo "starting csp network vpn service..."
	@sudo systemctl start cspnetwork.service
	@echo "service started"

service-stop:
	@echo "stopping csp network vpn service..."
	@sudo systemctl stop cspnetwork.service
	@echo "service stopped"

service-restart:
	@echo "restarting csp network vpn service..."
	@sudo systemctl restart cspnetwork.service
	@echo "service restarted"

service-status:
	@echo "csp network vpn service status:"
	@systemctl status cspnetwork.service --no-pager

service-logs:
	@echo "csp network vpn service logs:"
	@sudo journalctl -u cspnetwork.service -f

service-logs-static:
	@echo "csp network vpn recent logs:"
	@sudo journalctl -u cspnetwork.service -n 50 --no-pager

dev: dev-build service-restart
	@echo "development deployment completed"

deploy: rebuild install service-restart
	@echo "production deployment completed"

format:
	@if command -v clang-format >/dev/null 2>&1; then \
		echo "formatting code..."; \
		find src include tests -name "*.cpp" -o -name "*.h" | xargs clang-format -i; \
		echo "code formatting completed"; \
	else \
		echo "clang-format not found, skipping formatting"; \
	fi

lint:
	@if command -v cppcheck >/dev/null 2>&1; then \
		echo "running code analysis..."; \
		cppcheck --enable=all --std=c++20 --suppress=missingIncludeSystem src/ include/; \
		echo "code analysis completed"; \
	else \
		echo "cppcheck not found, skipping lint"; \
	fi

help:
	@echo "csp network vpn - available targets:"
	@echo ""
	@echo "build targets:"
	@echo "  build           - build the project (release mode)"
	@echo "  dev-build       - build the project (debug mode)"
	@echo "  clean           - clean build directory"
	@echo "  rebuild         - clean and build"
	@echo ""
	@echo "test targets:"
	@echo "  test            - run all tests"
	@echo "  test-unit       - run unit tests only"
	@echo "  test-integration - run integration tests only"
	@echo "  test-performance - run performance tests only"
	@echo ""
	@echo "installation targets:"
	@echo "  install         - install system-wide (requires sudo)"
	@echo "  uninstall       - uninstall system-wide (requires sudo)"
	@echo "  dev-install     - install development version (requires sudo)"
	@echo ""
	@echo "service management:"
	@echo "  service-start   - start the vpn service"
	@echo "  service-stop    - stop the vpn service"
	@echo "  service-restart - restart the vpn service"
	@echo "  service-status  - show service status"
	@echo "  service-logs    - follow service logs"
	@echo "  service-logs-static - show recent logs"
	@echo ""
	@echo "development workflow:"
	@echo "  dev             - build (debug) + restart service"
	@echo "  deploy          - rebuild + install + restart (production)"
	@echo ""
	@echo "code quality:"
	@echo "  format          - format code with clang-format"
	@echo "  lint            - run static analysis with cppcheck"
	@echo ""
	@echo "other:"
	@echo "  help            - show this help message"
	@echo ""
	@echo "examples:"
	@echo "  make build                  # build the project"
	@echo "  sudo make install           # install system-wide"
	@echo "  make service-start          # start the service"
	@echo "  make dev                    # quick development cycle"
	@echo "  sudo make deploy            # full production deployment"
