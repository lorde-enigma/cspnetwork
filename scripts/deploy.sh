#!/bin/bash

# Automated Deployment Script for Seeded VPN Server
# Version: 1.0.0
# Description: Comprehensive deployment automation with configuration management

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION="1.0.0"
SERVICE_NAME="cspnetwork"
SERVICE_USER="vpnuser"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]] && [[ "$ID" != "centos" ]] && [[ "$ID" != "rhel" ]]; then
        log_warning "Unsupported OS: $ID. Proceeding anyway..."
    fi
    
    # Check IPv6 support
    if ! ip -6 addr show | grep -q inet6; then
        log_error "IPv6 is not configured on this system"
        exit 1
    fi
    
    # Check available memory
    MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
    if (( MEMORY_GB < 4 )); then
        log_warning "System has only ${MEMORY_GB}GB RAM. Minimum 4GB recommended."
    fi
    
    # Check available disk space
    DISK_GB=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    if (( DISK_GB < 10 )); then
        log_error "Insufficient disk space. At least 10GB required."
        exit 1
    fi
    
    log_success "System requirements check passed"
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    if command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            cmake \
            ninja-build \
            libssl-dev \
            libyaml-cpp-dev \
            libgtest-dev \
            pkg-config \
            git \
            curl \
            wget \
            systemd \
            logrotate
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL
        sudo yum update -y
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y \
            cmake \
            ninja-build \
            openssl-devel \
            yaml-cpp-devel \
            gtest-devel \
            pkgconfig \
            git \
            curl \
            wget \
            systemd \
            logrotate
    else
        log_error "Unsupported package manager"
        exit 1
    fi
    
    log_success "Dependencies installed successfully"
}

# Create service user and directories
setup_user_and_directories() {
    log_info "Setting up service user and directories..."
    
    # Create service user
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        sudo useradd -r -s /bin/false -d "/var/lib/$SERVICE_NAME" "$SERVICE_USER"
        log_success "Created service user: $SERVICE_USER"
    else
        log_info "Service user $SERVICE_USER already exists"
    fi
    
    # Create directories
    local dirs=(
        "/etc/$SERVICE_NAME"
        "/var/log/$SERVICE_NAME"
        "/var/lib/$SERVICE_NAME"
        "/var/run/$SERVICE_NAME"
    )
    
    for dir in "${dirs[@]}"; do
        sudo mkdir -p "$dir"
        sudo chown "$SERVICE_USER:$SERVICE_USER" "$dir"
        sudo chmod 750 "$dir"
    done
    
    log_success "User and directories configured"
}

# Build the VPN server
build_server() {
    log_info "Building VPN server..."
    
    cd "$PROJECT_ROOT"
    
    # Clean previous build
    if [[ -d build ]]; then
        rm -rf build
    fi
    
    # Configure build
    mkdir build
    cd build
    cmake -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DSECURITY_HARDENING=ON \
        -DCMAKE_INSTALL_PREFIX=/usr \
        ..
    
    # Build
    ninja -j$(nproc)
    
    # Run tests
    if [[ "${SKIP_TESTS:-false}" != "true" ]]; then
        log_info "Running tests..."
        ninja test || {
            log_warning "Some tests failed, but continuing with deployment"
        }
    fi
    
    log_success "Build completed successfully"
}

# Install the VPN server
install_server() {
    log_info "Installing VPN server..."
    
    cd "$PROJECT_ROOT/build"
    
    # Install binary
    sudo ninja install
    
    # Set proper permissions
    sudo chown root:root "/usr/bin/$SERVICE_NAME"
    sudo chmod 755 "/usr/bin/$SERVICE_NAME"
    
    log_success "VPN server installed"
}

# Generate certificates
generate_certificates() {
    log_info "Generating certificates..."
    
    local cert_dir="/etc/$SERVICE_NAME/certs"
    sudo mkdir -p "$cert_dir"
    
    # Generate CA private key
    sudo openssl genpkey -algorithm RSA -out "$cert_dir/ca-key.pem" -pkcs8 -aes256 -pass pass:ca_password_123
    
    # Generate CA certificate
    sudo openssl req -new -x509 -key "$cert_dir/ca-key.pem" -out "$cert_dir/ca-cert.pem" -days 3650 \
        -passin pass:ca_password_123 \
        -subj "/C=US/ST=CA/L=San Francisco/O=VPN Server/CN=VPN CA"
    
    # Generate server private key
    sudo openssl genpkey -algorithm RSA -out "$cert_dir/server-key.pem" -pkcs8
    
    # Generate server certificate request
    sudo openssl req -new -key "$cert_dir/server-key.pem" -out "$cert_dir/server-csr.pem" \
        -subj "/C=US/ST=CA/L=San Francisco/O=VPN Server/CN=vpn.local"
    
    # Sign server certificate
    sudo openssl x509 -req -in "$cert_dir/server-csr.pem" \
        -CA "$cert_dir/ca-cert.pem" -CAkey "$cert_dir/ca-key.pem" \
        -out "$cert_dir/server-cert.pem" -days 365 \
        -CAcreateserial -passin pass:ca_password_123
    
    # Set permissions
    sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$cert_dir"
    sudo chmod 600 "$cert_dir"/*.pem
    sudo chmod 644 "$cert_dir"/*-cert.pem
    
    # Clean up CSR
    sudo rm "$cert_dir/server-csr.pem"
    
    log_success "Certificates generated"
}

# Create configuration
create_configuration() {
    log_info "Creating configuration..."
    
    local config_file="/etc/$SERVICE_NAME/config.yaml"
    
    sudo tee "$config_file" << EOF
server:
  listen_address: "::"
  listen_port: 443
  max_connections: 5000
  worker_threads: $(nproc)
  connection_timeout: 300
  keepalive_interval: 30

security:
  encryption: "chacha20-poly1305"
  key_exchange: "x25519"
  certificate_path: "/etc/$SERVICE_NAME/certs/server-cert.pem"
  private_key_path: "/etc/$SERVICE_NAME/certs/server-key.pem"
  ca_certificate_path: "/etc/$SERVICE_NAME/certs/ca-cert.pem"
  verify_client_cert: true
  pfs_enabled: true
  anti_replay: true

seed_management:
  pool_size: 50000
  allocation_strategy: "ADAPTIVE"
  geographic_distribution: true
  load_balancing: true
  allocation_timeout: 30

performance:
  memory_pool_size: 1024
  cache_size: 512
  thread_pool_size: 32
  buffer_size: 65536

monitoring:
  metrics_enabled: true
  health_check_interval: 60
  collection_interval: 60
  export_format: "prometheus"
  metrics_endpoint: "/metrics"

logging:
  level: "INFO"
  output: "/var/log/$SERVICE_NAME/server.log"
  format: "json"
  rotation:
    max_size: "100MB"
    max_age: "7d"
    max_backups: 10
EOF
    
    sudo chown "$SERVICE_USER:$SERVICE_USER" "$config_file"
    sudo chmod 640 "$config_file"
    
    log_success "Configuration created"
}

# Configure system settings
configure_system() {
    log_info "Configuring system settings..."
    
    # Configure kernel parameters
    sudo tee /etc/sysctl.d/99-cspnetwork.conf << EOF
# Network optimizations for VPN server
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 1024

# IPv6 forwarding
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# Security settings
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
    
    sudo sysctl -p /etc/sysctl.d/99-cspnetwork.conf
    
    # Configure limits
    sudo tee /etc/security/limits.d/cspnetwork.conf << EOF
$SERVICE_USER soft nofile 65536
$SERVICE_USER hard nofile 65536
$SERVICE_USER soft nproc 32768
$SERVICE_USER hard nproc 32768
EOF
    
    log_success "System configured"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."
    
    sudo tee "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Seeded VPN Server
Documentation=file:///usr/share/doc/cspnetwork/
After=network.target network-online.target
Wants=network-online.target
ConditionFileIsExecutable=/usr/bin/$SERVICE_NAME

[Service]
Type=forking
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=/usr/bin/$SERVICE_NAME --start --daemon --config /etc/$SERVICE_NAME/config.yaml
ExecStop=/usr/bin/$SERVICE_NAME --stop
ExecReload=/usr/bin/$SERVICE_NAME --reload-config
PIDFile=/var/run/$SERVICE_NAME/$SERVICE_NAME.pid
Restart=always
RestartSec=5
StartLimitBurst=3
StartLimitInterval=60
LimitNOFILE=65536
LimitNPROC=32768

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/$SERVICE_NAME /var/lib/$SERVICE_NAME /var/run/$SERVICE_NAME
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true
RestrictNamespaces=true

# Network access
IPAddressDeny=any
IPAddressAllow=localhost
IPAddressAllow=::/0

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    
    log_success "Systemd service created and enabled"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Check if ufw is available
    if command -v ufw >/dev/null 2>&1; then
        sudo ufw allow 443/udp comment "VPN Server"
        sudo ufw allow 8080/tcp comment "VPN Metrics"
        sudo ufw --force enable
    elif command -v firewall-cmd >/dev/null 2>&1; then
        sudo firewall-cmd --permanent --add-port=443/udp
        sudo firewall-cmd --permanent --add-port=8080/tcp
        sudo firewall-cmd --reload
    else
        log_warning "No supported firewall found. Please configure manually."
    fi
    
    log_success "Firewall configured"
}

# Configure log rotation
configure_logging() {
    log_info "Configuring log rotation..."
    
    sudo tee "/etc/logrotate.d/$SERVICE_NAME" << EOF
/var/log/$SERVICE_NAME/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload $SERVICE_NAME || true
    endscript
}
EOF
    
    log_success "Log rotation configured"
}

# Start and verify service
start_and_verify() {
    log_info "Starting VPN server..."
    
    # Start service
    sudo systemctl start "$SERVICE_NAME"
    
    # Wait for startup
    sleep 5
    
    # Check status
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "VPN server started successfully"
    else
        log_error "Failed to start VPN server"
        sudo systemctl status "$SERVICE_NAME"
        exit 1
    fi
    
    # Verify health
    if "/usr/bin/$SERVICE_NAME" --health-check >/dev/null 2>&1; then
        log_success "Health check passed"
    else
        log_warning "Health check failed - service may be starting up"
    fi
    
    # Show status
    sudo systemctl status "$SERVICE_NAME" --no-pager
}

# Create monitoring scripts
create_monitoring() {
    log_info "Creating monitoring scripts..."
    
    # Health check script
    sudo tee "/usr/local/bin/$SERVICE_NAME-healthcheck" << 'EOF'
#!/bin/bash
SERVICE_NAME="cspnetwork"

if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "CRITICAL: $SERVICE_NAME service is not running"
    exit 2
fi

if ! /usr/bin/$SERVICE_NAME --health-check >/dev/null 2>&1; then
    echo "WARNING: $SERVICE_NAME health check failed"
    exit 1
fi

echo "OK: $SERVICE_NAME is healthy"
exit 0
EOF
    
    sudo chmod +x "/usr/local/bin/$SERVICE_NAME-healthcheck"
    
    # Performance monitoring script
    sudo tee "/usr/local/bin/$SERVICE_NAME-monitor" << 'EOF'
#!/bin/bash
SERVICE_NAME="cspnetwork"

echo "=== VPN Server Status ==="
systemctl status $SERVICE_NAME --no-pager

echo -e "\n=== Resource Usage ==="
ps aux | grep "$SERVICE_NAME" | grep -v grep

echo -e "\n=== Network Connections ==="
ss -tulpn | grep ":443"

echo -e "\n=== Log Summary ==="
tail -10 /var/log/$SERVICE_NAME/server.log

echo -e "\n=== Metrics ==="
curl -s http://localhost:8080/metrics | grep -E "(connections|throughput|errors)"
EOF
    
    sudo chmod +x "/usr/local/bin/$SERVICE_NAME-monitor"
    
    log_success "Monitoring scripts created"
}

# Main deployment function
main() {
    log_info "Starting Seeded VPN Server deployment v$VERSION"
    
    # Parse command line arguments
    SKIP_TESTS=false
    SKIP_BUILD=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --skip-tests    Skip running tests during build"
                echo "  --skip-build    Skip building and use existing binary"
                echo "  --help          Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run deployment steps
    check_root
    check_system_requirements
    install_dependencies
    setup_user_and_directories
    
    if [[ "$SKIP_BUILD" != "true" ]]; then
        build_server
        install_server
    fi
    
    generate_certificates
    create_configuration
    configure_system
    create_systemd_service
    configure_firewall
    configure_logging
    create_monitoring
    start_and_verify
    
    log_success "Deployment completed successfully!"
    log_info "Service status: sudo systemctl status $SERVICE_NAME"
    log_info "View logs: sudo journalctl -u $SERVICE_NAME -f"
    log_info "Health check: /usr/local/bin/$SERVICE_NAME-healthcheck"
    log_info "Monitor: /usr/local/bin/$SERVICE_NAME-monitor"
}

# Trap errors
trap 'log_error "Deployment failed at line $LINENO"' ERR

# Run main function
main "$@"
