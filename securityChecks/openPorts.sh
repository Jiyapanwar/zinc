#!/bin/bash


# Advanced Open Ports Check - Comprehensive Security Scanner
# Enhanced with additional features for security auditing


# Colors for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color


# Logging setup
LOG_FILE="/var/log/open_ports_and_services_audit.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")


# Function to log messages
log_message() {
    local level=$1
    local message=$2
    echo -e "${TIMESTAMP} [$level] $message" | tee -a "$LOG_FILE"
}


# Define target and output directory
TARGET=${1:-"localhost"}  # Default target is localhost
OUTPUT_DIR="./security_reports"
mkdir -p "$OUTPUT_DIR"


# Banner
echo "==============================================="
echo "      Open Ports Security Scanner              "
echo "==============================================="
echo "Target: $TARGET"
echo "Reports will be saved in: $OUTPUT_DIR"


# Install required packages if not installed
install_packages() {
    echo "Installing required packages if not already installed..."
    REQUIRED_PACKAGES=(nmap ufw fail2ban libpam-google-authenticator unattended-upgrades)
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! command -v $package &> /dev/null; then
            echo "Installing $package..."
            sudo apt-get update && sudo apt-get install -y $package
        fi
    done
}


# Start scan and save results
scan_open_ports() {
    echo "Scanning open ports on $TARGET..."
    nmap -sS -sV -T4 $TARGET -oN "$OUTPUT_DIR/open_ports_detailed_report.txt"
    log_message "INFO" "Open ports scan completed."
}


# Analyze open ports
analyze_open_ports() {
    echo "Analyzing open ports..."
    grep "open" "$OUTPUT_DIR/open_ports_detailed_report.txt" > "$OUTPUT_DIR/open_ports_filtered.txt"

    # Categorize open ports and take actions
    echo "Categorizing and checking vulnerabilities for detected ports..."
    CRITICAL_PORTS=(22 23 21 80 443 3306)
    while read -r line; do
        PORT=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        SERVICE=$(echo "$line" | awk '{print $3}')
        if [[ " ${CRITICAL_PORTS[@]} " =~ " ${PORT} " ]]; then
            echo "Critical Port $PORT ($SERVICE) - Immediate Action Taken"
            log_message "WARNING" "Critical Port $PORT ($SERVICE) detected. Applying firewall rule."
            sudo ufw deny $PORT
        fi
    done < "$OUTPUT_DIR/open_ports_filtered.txt"
}


# Enable the firewall if not already active
enable_firewall() {
    echo "Ensuring firewall is active..."
    sudo ufw enable
    log_message "INFO" "Firewall enabled."
}


# Setup logging for dropped packets
setup_logging() {
    echo "Setting up logging for denied traffic..."
    sudo iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 7
    log_message "INFO" "Logging for denied traffic set up."
}


# Configure Two-Factor Authentication (2FA) for SSH if port 22 is open
configure_2fa() {
    if grep -q "22/tcp" "$OUTPUT_DIR/open_ports_filtered.txt"; then
        echo "Port 22 (SSH) is open. Configuring Two-Factor Authentication (2FA)..."
        sudo apt-get install -y libpam-google-authenticator
        sudo google-authenticator
        log_message "INFO" "2FA setup completed for SSH."
        
        # Disable root login via SSH for enhanced security
        echo "Disabling root login via SSH..."
        sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo systemctl restart sshd
        log_message "INFO" "Root login via SSH disabled."
    fi
}


# Block access to unnecessary ports
block_unnecessary_ports() {
    echo "Blocking access to unnecessary ports..."
    sudo ufw deny 23
    log_message "INFO" "Access to port 23 blocked."
}


# Apply Firewall restrictions for critical ports
apply_firewall_restrictions() {
    echo "Restricting access to critical ports (22, 443, etc.)..."
    for port in "${CRITICAL_PORTS[@]}"; do
        sudo ufw deny $port
        log_message "INFO" "Access to critical port $port restricted."
    done
}


# Install and configure Fail2Ban
configure_fail2ban() {
    echo "Configuring Fail2Ban..."
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    log_message "INFO" "Fail2Ban configured and started."
}


# Automate regular system patching and upgrades
configure_automatic_updates() {
    echo "Configuring automatic system updates..."
    sudo dpkg-reconfigure --priority=low unattended-upgrades
    sudo systemctl enable unattended-upgrades
    sudo systemctl start unattended-upgrades
    log_message "INFO" "Automatic updates configured."
}


# Generate and save security recommendations
generate_recommendations() {
    {
        echo "Recommendations Based on Open Ports Scan:"
        echo "1. Close unnecessary ports identified during the scan."
        echo "2. Restrict access to critical ports (e.g., 22, 443) using IP whitelisting or VPN."
        echo "3. Regularly review and update firewall rules."
        echo "4. Use tools like Fail2Ban to prevent repeated unauthorized access attempts."
        echo "5. Implement Two-Factor Authentication (2FA) for SSH to enhance access control."
        echo "6. Set up automatic patch management to keep all packages up to date."
        echo "7. Disable root login via SSH to prevent brute-force attacks."
        echo "8. Monitor logs for unauthorized access attempts."
        echo "9. Regularly audit open ports and services running on the system."
        echo "10. Consider using a VPN for remote access to critical services."
    } > "$OUTPUT_DIR/recommendations.txt"
    log_message "INFO" "Security recommendations generated."
}


# Main script execution
echo -e "${BLUE}=== Open Ports and Log Files Security Audit ===${NC}"
echo -e "Started at: ${TIMESTAMP}\n"
log_message "INFO" "Starting open ports and log files security audit"


# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root${NC}"
    log_message "ERROR" "Script must be run as root"
    exit 1
fi


# Execute functions
install_packages
scan_open_ports
analyze_open_ports
enable_firewall
setup_logging
configure_2fa
block_unnecessary_ports
apply_firewall_restrictions
configure_fail2ban
configure_automatic_updates
generate_recommendations


echo "Open Ports Check and Enhancements completed. Reports saved in: $OUTPUT_DIR"
echo "Detailed report of open ports can be found in: $OUTPUT_DIR/open_ports_detailed_report.txt"
echo "Filtered open ports report can be found in: $OUTPUT_DIR/open_ports_filtered.txt"
echo "Security recommendations can be found in: $OUTPUT_DIR/recommendations.txt"
