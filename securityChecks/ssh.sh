#!/bin/bash

# SSH Security Audit Script
# Based on sshPlan.txt checklist
# For Debian-based Linux systems

# Colors for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging setup
LOG_FILE="/var/log/ssh_security_audit.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# Common paths for sshd_config
SSHD_CONFIG_PATHS=(
    "/etc/ssh/sshd_config"
    "/etc/sshd_config"
    "/usr/local/etc/sshd_config"
    "/opt/ssh/etc/sshd_config"
)

# SSH directory paths
SSH_DIR="/etc/ssh"
USER_SSH_DIR="$HOME/.ssh"

# Function to check if SSH server is running
check_ssh_status() {
    if systemctl is-active --quiet sshd; then
        return 0  # Running
    else
        return 1  # Not running
    fi
}

# Function to start SSH server
start_ssh_server() {
    echo -e "${BLUE}Starting SSH server...${NC}"
    if ! systemctl is-active --quiet sshd; then
        if sudo systemctl start sshd; then
            echo -e "${GREEN}SSH server started successfully${NC}"
            log_message "INFO" "SSH server started"
            # Wait for service to fully start
            sleep 2
            return 0
        else
            echo -e "${RED}Failed to start SSH server${NC}"
            log_message "ERROR" "Failed to start SSH server"
            exit 1
        fi
    else
        echo -e "${YELLOW}SSH server is already running${NC}"
        log_message "INFO" "SSH server was already running"
        return 0
    fi
}

# Function to stop SSH server if it wasn't running before
stop_ssh_server() {
    if [ "$1" = "true" ]; then
        echo -e "${BLUE}Stopping SSH server...${NC}"
        if sudo systemctl stop sshd; then
            echo -e "${GREEN}SSH server stopped successfully${NC}"
            log_message "INFO" "SSH server stopped"
        else
            echo -e "${RED}Failed to stop SSH server${NC}"
            log_message "ERROR" "Failed to stop SSH server"
        fi
    fi
}

# Find sshd_config file
find_sshd_config() {
    for config_path in "${SSHD_CONFIG_PATHS[@]}"; do
        if [ -f "$config_path" ]; then
            echo "$config_path"
            return 0
        fi
    done
    return 1
}

# Get sshd_config path
SSHD_CONFIG=$(find_sshd_config)

if [ -z "$SSHD_CONFIG" ]; then
    echo -e "${RED}Error: sshd_config file not found in common locations${NC}"
    echo -e "Checking if SSH is installed..."
    
    # Check if SSH server (not just client) is installed
    if ! dpkg -l | grep -q openssh-server && ! rpm -qa | grep -q openssh-server; then
        echo -e "${RED}OpenSSH server is not installed on this system${NC}"
        echo -e "Please install OpenSSH server using one of these commands:"
        echo -e "For Debian/Ubuntu: ${YELLOW}sudo apt-get install openssh-server${NC}"
        echo -e "For RHEL/CentOS: ${YELLOW}sudo yum install openssh-server${NC}"
        exit 1
    else
        echo -e "${YELLOW}OpenSSH server is installed but sshd_config not found${NC}"
        echo -e "Try reinstalling the OpenSSH server:"
        echo -e "For Debian/Ubuntu: ${YELLOW}sudo apt-get reinstall openssh-server${NC}"
        echo -e "For RHEL/CentOS: ${YELLOW}sudo yum reinstall openssh-server${NC}"
        exit 1
    fi
fi

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    echo -e "${TIMESTAMP} [$level] $message" | tee -a "$LOG_FILE"
}

# Function to check configuration values in sshd_config
check_sshd_config() {
    local param=$1
    local expected=$2
    if [ -f "$SSHD_CONFIG" ]; then
        local actual=$(grep "^${param}" "$SSHD_CONFIG" | awk '{print $2}')
        if [ -n "$actual" ]; then
            if [ "$actual" = "$expected" ]; then
                echo -e "${GREEN}✓${NC} $param is correctly set to $expected"
                log_message "INFO" "$param is correctly set to $expected"
            else
                echo -e "${RED}✗${NC} $param is set to $actual (should be $expected)"
                log_message "WARNING" "$param is set to $actual (should be $expected)"
            fi
        else
            echo -e "${YELLOW}⚠${NC} $param is not set in $SSHD_CONFIG"
            log_message "WARNING" "$param is not set"
        fi
    else
        echo -e "${RED}✗${NC} Cannot check $param: sshd_config not found"
        log_message "ERROR" "Cannot check $param: sshd_config not found"
    fi
}

# Function to check file permissions
check_file_permissions() {
    local file=$1
    local expected_perms=$2
    if [ -f "$file" ]; then
        local actual_perms=$(stat -c "%a" "$file")
        if [ "$actual_perms" = "$expected_perms" ]; then
            echo -e "${GREEN}✓${NC} $file has correct permissions ($expected_perms)"
            log_message "INFO" "$file has correct permissions ($expected_perms)"
        else
            echo -e "${RED}✗${NC} $file has incorrect permissions: $actual_perms (should be $expected_perms)"
            log_message "WARNING" "$file has incorrect permissions: $actual_perms (should be $expected_perms)"
        fi
    else
        echo -e "${YELLOW}⚠${NC} File not found: $file"
        log_message "WARNING" "File not found: $file"
    fi
}

# Function to check directory permissions
check_dir_permissions() {
    local dir=$1
    local expected_perms=$2
    if [ -d "$dir" ]; then
        local actual_perms=$(stat -c "%a" "$dir")
        if [ "$actual_perms" = "$expected_perms" ]; then
            echo -e "${GREEN}✓${NC} $dir has correct permissions ($expected_perms)"
            log_message "INFO" "$dir has correct permissions ($expected_perms)"
        else
            echo -e "${RED}✗${NC} $dir has incorrect permissions: $actual_perms (should be $expected_perms)"
            log_message "WARNING" "$dir has incorrect permissions: $actual_perms (should be $expected_perms)"
        fi
    else
        echo -e "${YELLOW}⚠${NC} Directory not found: $dir"
        log_message "WARNING" "Directory not found: $dir"
    fi
}

# Function to check file ownership
check_ownership() {
    local file=$1
    local expected_owner=$2
    local expected_group=$3
    if [ -e "$file" ]; then
        local actual_owner=$(stat -c "%U:%G" "$file")
        local expected="${expected_owner}:${expected_group}"
        if [ "$actual_owner" = "$expected" ]; then
            echo -e "${GREEN}✓${NC} $file has correct ownership ($expected)"
            log_message "INFO" "$file has correct ownership ($expected)"
        else
            echo -e "${RED}✗${NC} $file has incorrect ownership: $actual_owner (should be $expected)"
            log_message "WARNING" "$file has incorrect ownership: $actual_owner (should be $expected)"
        fi
    else
        echo -e "${YELLOW}⚠${NC} File not found: $file"
        log_message "WARNING" "File not found: $file"
    fi
}

# Main header
echo -e "${BLUE}=== SSH Security Audit ===${NC}"
echo -e "${BLUE}Started at: ${TIMESTAMP}${NC}\n"
log_message "INFO" "Starting SSH security audit"
echo -e "Using SSH config file: $SSHD_CONFIG"

# Check if SSH server is installed
if ! command -v sshd >/dev/null 2>&1; then
    echo -e "${RED}SSH server is not installed${NC}"
    echo -e "Installing SSH server..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y openssh-server
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y openssh-server
    else
        echo -e "${RED}Unable to install SSH server. Please install it manually.${NC}"
        exit 1
    fi
fi

# Check initial SSH server state
SSH_WAS_STOPPED=false
if ! check_ssh_status; then
    SSH_WAS_STOPPED=true
fi

# Start SSH server if it's not running
start_ssh_server

# Add trap to ensure SSH server is stopped on script exit if it wasn't running before
trap 'stop_ssh_server $SSH_WAS_STOPPED' EXIT

# 1. SSH Configuration Security
echo -e "\n${YELLOW}1. Checking SSH Configuration Security${NC}"
log_message "INFO" "Checking SSH Configuration Security"

# Check SSH version
if command -v ssh >/dev/null 2>&1; then
    ssh_version=$(ssh -V 2>&1)
    echo -e "SSH Version: $ssh_version"
    log_message "INFO" "SSH Version: $ssh_version"
else
    echo -e "${RED}SSH client not found${NC}"
    log_message "ERROR" "SSH client not found"
fi

# Check sshd_config parameters
check_sshd_config "PermitRootLogin" "no"
check_sshd_config "PasswordAuthentication" "no"
check_sshd_config "Protocol" "2"

# Check SSH port
ssh_port=$(grep "^Port" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
if [ -z "$ssh_port" ]; then
    ssh_port="22"  # Default port if not specified
    echo -e "${YELLOW}⚠${NC} SSH port not explicitly set, using default port 22"
    log_message "WARNING" "SSH port not explicitly set, using default port 22"
elif [ "$ssh_port" = "22" ]; then
    echo -e "${YELLOW}⚠${NC} SSH is running on default port 22"
    log_message "WARNING" "SSH is running on default port 22"
else
    echo -e "${GREEN}✓${NC} SSH is running on non-standard port $ssh_port"
    log_message "INFO" "SSH is running on non-standard port $ssh_port"
fi

# 2. SSH Key Management
echo -e "\n${YELLOW}2. Checking SSH Key Management${NC}"
log_message "INFO" "Checking SSH Key Management"

# Check SSH key files and permissions
for key_file in "$SSH_DIR"/ssh_host_*_key; do
    if [ -f "$key_file" ]; then
        check_file_permissions "$key_file" "600"
        check_file_permissions "${key_file}.pub" "644"
    fi
done

# Check user's SSH directory and keys
if [ -d "$USER_SSH_DIR" ]; then
    check_dir_permissions "$USER_SSH_DIR" "700"
    [ -f "$USER_SSH_DIR/authorized_keys" ] && check_file_permissions "$USER_SSH_DIR/authorized_keys" "600"
fi

# 3. Access Control & Authentication
echo -e "\n${YELLOW}3. Checking Access Control & Authentication${NC}"
log_message "INFO" "Checking Access Control & Authentication"

# Check AllowUsers/DenyUsers settings
if grep -E "^(Allow|Deny)(Users|Groups)" "$SSHD_CONFIG" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Access control lists are configured:"
    grep -E "^(Allow|Deny)(Users|Groups)" "$SSHD_CONFIG"
else
    echo -e "${YELLOW}⚠${NC} No explicit Allow/Deny rules found"
fi

# Check MaxAuthTries
max_tries=$(grep "^MaxAuthTries" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
if [ -n "$max_tries" ] && [ "$max_tries" -le 4 ] && [ "$max_tries" -ge 3 ]; then
    echo -e "${GREEN}✓${NC} MaxAuthTries is set to recommended value: $max_tries"
else
    echo -e "${RED}✗${NC} MaxAuthTries should be between 3 and 4"
fi

# 4. File & Directory Permissions
echo -e "\n${YELLOW}4. Checking File & Directory Permissions${NC}"
log_message "INFO" "Checking File & Directory Permissions"

# Check SSH directory permissions
if [ -d "$SSH_DIR" ]; then
    check_dir_permissions "$SSH_DIR" "755"
    check_ownership "$SSH_DIR" "root" "root"
else
    echo -e "${RED}SSH directory not found: $SSH_DIR${NC}"
    log_message "ERROR" "SSH directory not found: $SSH_DIR"
fi

# Check user's SSH directory
if [ -d "$USER_SSH_DIR" ]; then
    check_dir_permissions "$USER_SSH_DIR" "700"
    check_ownership "$USER_SSH_DIR" "$USER" "$USER"
else
    echo -e "${YELLOW}User SSH directory not found: $USER_SSH_DIR${NC}"
    log_message "WARNING" "User SSH directory not found: $USER_SSH_DIR"
fi

# 5. Network Security
echo -e "\n${YELLOW}5. Checking Network Security${NC}"
log_message "INFO" "Checking Network Security"

# Check SSH listening ports
echo "SSH listening ports:"
if command -v netstat >/dev/null 2>&1; then
    netstat -tuln | grep ":$ssh_port" || echo -e "${YELLOW}No active SSH listeners found${NC}"
elif command -v ss >/dev/null 2>&1; then
    ss -tuln | grep ":$ssh_port" || echo -e "${YELLOW}No active SSH listeners found${NC}"
else
    echo -e "${RED}Neither netstat nor ss command found${NC}"
    log_message "ERROR" "Network tools not found"
fi

# Check firewall rules
echo "Checking firewall rules for SSH:"
if command -v ufw >/dev/null 2>&1; then
    ufw_status=$(ufw status 2>/dev/null | grep -i ssh)
    if [ -n "$ufw_status" ]; then
        echo -e "${GREEN}✓${NC} UFW has SSH rules configured:"
        echo "$ufw_status"
    else
        echo -e "${RED}✗${NC} No SSH rules found in UFW"
    fi
elif command -v iptables >/dev/null 2>&1; then
    iptables_rules=$(iptables -L 2>/dev/null | grep -i ssh)
    if [ -n "$iptables_rules" ]; then
        echo -e "${GREEN}✓${NC} iptables has SSH rules configured:"
        echo "$iptables_rules"
    else
        echo -e "${RED}✗${NC} No SSH rules found in iptables"
    fi
else
    echo -e "${YELLOW}⚠${NC} No firewall (ufw/iptables) found"
    log_message "WARNING" "No firewall found"
fi

# Check fail2ban
if command -v fail2ban-client >/dev/null 2>&1; then
    if fail2ban-client status sshd >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} fail2ban is installed and monitoring SSH"
        log_message "INFO" "fail2ban is installed and monitoring SSH"
    else
        echo -e "${RED}✗${NC} fail2ban is installed but not monitoring SSH"
        log_message "WARNING" "fail2ban is installed but not monitoring SSH"
    fi
else
    echo -e "${RED}✗${NC} fail2ban is not installed"
    log_message "WARNING" "fail2ban is not installed"
fi

# 6. Crypto Settings
echo -e "\n${YELLOW}6. Checking Crypto Settings${NC}"
log_message "INFO" "Checking Crypto Settings"

# Check key exchange algorithms
echo "Checking key exchange algorithms:"
if command -v ssh >/dev/null 2>&1; then
    kex_algorithms=$(ssh -Q kex 2>/dev/null)
    if [ -n "$kex_algorithms" ]; then
        echo -e "${GREEN}✓${NC} Available key exchange algorithms:"
        echo "$kex_algorithms" | grep -vE 'sha1|diffie-hellman-group1'
        weak_kex=$(echo "$kex_algorithms" | grep -E 'sha1|diffie-hellman-group1')
        if [ -n "$weak_kex" ]; then
            echo -e "${RED}✗${NC} Weak key exchange algorithms found:"
            echo "$weak_kex"
        fi
    else
        echo -e "${YELLOW}⚠${NC} Could not retrieve key exchange algorithms"
    fi
else
    echo -e "${RED}✗${NC} SSH client not found"
fi

# Check MAC algorithms
echo "Checking MAC algorithms:"
if command -v ssh >/dev/null 2>&1; then
    mac_algorithms=$(ssh -Q mac 2>/dev/null)
    if [ -n "$mac_algorithms" ]; then
        echo -e "${GREEN}✓${NC} Available MAC algorithms:"
        echo "$mac_algorithms" | grep -vE 'md5|sha1'
        weak_mac=$(echo "$mac_algorithms" | grep -E 'md5|sha1')
        if [ -n "$weak_mac" ]; then
            echo -e "${RED}✗${NC} Weak MAC algorithms found:"
            echo "$weak_mac"
        fi
    else
        echo -e "${YELLOW}⚠${NC} Could not retrieve MAC algorithms"
    fi
fi

# Check ciphers
if [ -f "$SSHD_CONFIG" ]; then
    ciphers=$(grep "^Ciphers" "$SSHD_CONFIG" 2>/dev/null)
    if [ -n "$ciphers" ]; then
        echo -e "Configured ciphers: $ciphers"
        log_message "INFO" "Configured ciphers: $ciphers"
    else
        echo -e "${YELLOW}⚠${NC} Using default ciphers"
        log_message "WARNING" "Using default ciphers"
    fi
fi

# 7. Logging & Monitoring
echo -e "\n${YELLOW}7. Checking Logging & Monitoring${NC}"
log_message "INFO" "Checking Logging & Monitoring"

# Check SSH logging configuration
if [ -f "$SSHD_CONFIG" ]; then
    if grep -q "^LogLevel" "$SSHD_CONFIG" 2>/dev/null; then
        log_level=$(grep "^LogLevel" "$SSHD_CONFIG" | awk '{print $2}')
        echo -e "${GREEN}✓${NC} SSH logging is enabled (Level: $log_level)"
        log_message "INFO" "SSH logging is enabled (Level: $log_level)"
    else
        echo -e "${YELLOW}⚠${NC} SSH logging level not explicitly set"
        log_message "WARNING" "SSH logging level not explicitly set"
    fi
fi

# Analyze login patterns
echo "Analyzing login patterns:"
if [ -f "/var/log/auth.log" ]; then
    echo "Login attempts by hour (last 24 hours):"
    awk '/sshd.*Accepted/ {print $1,$2,$3}' /var/log/auth.log 2>/dev/null | sort | uniq -c || \
        echo -e "${YELLOW}⚠${NC} No successful logins found"
    
    echo -e "\nFailed login attempts by IP (top 10):"
    grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -n 10 || \
        echo -e "${YELLOW}⚠${NC} No failed login attempts found"
    
    # Check for concurrent login attempts
    concurrent_attempts=$(grep "sshd.*Failed password" /var/log/auth.log 2>/dev/null | awk '{print $1,$2,$3}' | uniq -c | sort -nr | head -n 1 | awk '{print $1}')
    if [ -n "$concurrent_attempts" ] && [ "$concurrent_attempts" -gt 10 ]; then
        echo -e "${RED}⚠${NC} High number of concurrent login attempts detected: $concurrent_attempts"
        log_message "WARNING" "High number of concurrent login attempts: $concurrent_attempts"
    fi
else
    echo -e "${YELLOW}⚠${NC} Auth log file not found at /var/log/auth.log"
    log_message "WARNING" "Auth log file not found"
fi

# Recent connections
echo -e "\nRecent SSH connections:"
if command -v last >/dev/null 2>&1; then
    last | grep "ssh" | head -n 5 || echo -e "${YELLOW}⚠${NC} No recent SSH connections found"
else
    echo -e "${RED}✗${NC} 'last' command not found"
fi

# Print summary table
echo -e "\n${BLUE}=== Security Check Summary ===${NC}"
echo -e "\nThreat Level Legend:"
echo "A - Critical Security Risk"
echo "B - High Security Risk"
echo "C - Medium Security Risk"
echo "D - Low Security Risk"

# Print table header
printf "\n%-25s | %-15s | %-10s\n" "Security Check" "Threat Level" "Satisfied"
printf "%.s-" {1..55}
printf "\n"

# Define checks array
checks=("Root Login" "Password Authentication" "Protocol Version" "Key Permissions" 
        "Failed Login Attempts" "Port Security" "Fail2ban" "Directory Permissions" 
        "Crypto Settings" "Log Monitoring" "Key Strength" "Access Control Lists" 
        "File Ownership" "Firewall Rules" "Strong Algorithms" "Login Patterns")

# Function to determine threat level
get_threat_level() {
    local check=$1
    case $check in
        "Root Login") echo "A";;
        "Password Authentication") echo "A";;
        "Protocol Version") echo "A";;
        "Key Permissions") echo "A";;
        "Failed Login Attempts") echo "B";;
        "Port Security") echo "B";;
        "Fail2ban") echo "B";;
        "Directory Permissions") echo "B";;
        "Crypto Settings") echo "C";;
        "Log Monitoring") echo "C";;
        "Key Strength") echo "A";;
        "Access Control Lists") echo "B";;
        "File Ownership") echo "B";;
        "Firewall Rules") echo "B";;
        "Strong Algorithms") echo "A";;
        "Login Patterns") echo "B";;
        *) echo "D";;
    esac
}

# Function to check if requirement is satisfied
check_satisfied() {
    local check=$1
    case $check in
        "Root Login")
            grep "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | grep -q "no" && echo "Yes" || echo "No"
            ;;
        "Password Authentication")
            grep "^PasswordAuthentication" "$SSHD_CONFIG" 2>/dev/null | grep -q "no" && echo "Yes" || echo "No"
            ;;
        "Protocol Version")
            grep "^Protocol" "$SSHD_CONFIG" 2>/dev/null | grep -q "2" && echo "Yes" || echo "No"
            ;;
        "Key Permissions")
            [ -f "$SSH_DIR/ssh_host_rsa_key" ] && [ "$(stat -c "%a" "$SSH_DIR/ssh_host_rsa_key" 2>/dev/null)" = "600" ] && echo "Yes" || echo "No"
            ;;
        "Failed Login Attempts")
            [ -n "$failed_attempts" ] && [ "$failed_attempts" -lt 10 ] && echo "Yes" || echo "No"
            ;;
        "Port Security")
            [ "$ssh_port" != "22" ] && echo "Yes" || echo "No"
            ;;
        "Fail2ban")
            command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1 && echo "Yes" || echo "No"
            ;;
        "Directory Permissions")
            [ -d "$SSH_DIR" ] && [ "$(stat -c "%a" "$SSH_DIR" 2>/dev/null)" = "755" ] && echo "Yes" || echo "No"
            ;;
        "Crypto Settings")
            grep -q "^Ciphers" "$SSHD_CONFIG" 2>/dev/null && echo "Yes" || echo "No"
            ;;
        "Log Monitoring")
            grep -q "^LogLevel" "$SSHD_CONFIG" 2>/dev/null && echo "Yes" || echo "No"
            ;;
        "Key Strength")
            [ -f "$SSH_DIR/ssh_host_rsa_key.pub" ] && ssh-keygen -lf "$SSH_DIR/ssh_host_rsa_key.pub" 2>/dev/null | awk '{if($1>=3072)print"Yes";else print"No"}' || echo "No"
            ;;
        "Access Control Lists")
            grep -E "^(Allow|Deny)(Users|Groups)" "$SSHD_CONFIG" 2>/dev/null >/dev/null && echo "Yes" || echo "No"
            ;;
        "File Ownership")
            [ -f "$SSHD_CONFIG" ] && [ "$(stat -c "%U:%G" "$SSHD_CONFIG" 2>/dev/null)" = "root:root" ] && echo "Yes" || echo "No"
            ;;
        "Firewall Rules")
            { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q ssh; } || { command -v iptables >/dev/null 2>&1 && iptables -L 2>/dev/null | grep -q ssh; } && echo "Yes" || echo "No"
            ;;
        "Strong Algorithms")
            ! ssh -Q mac 2>/dev/null | grep -qE 'md5|sha1' && echo "Yes" || echo "No"
            ;;
        "Login Patterns")
            [ -n "$concurrent_attempts" ] && [ "$concurrent_attempts" -lt 10 ] && echo "Yes" || echo "No"
            ;;
        *)
            echo "Unknown"
            ;;
    esac
}

# Print table rows
for check in "${checks[@]}"; do
    threat_level=$(get_threat_level "$check")
    satisfied=$(check_satisfied "$check")
    printf "%-25s | %-15s | %-10s\n" "$check" "$threat_level" "$satisfied"
done

# Generate recommendations
echo -e "\n${YELLOW}Critical Security Recommendations:${NC}"
declare -a recommendations

# Check for critical issues and add recommendations
if [ "$(check_satisfied 'Root Login')" = "No" ]; then
    recommendations+=("CRITICAL: Disable root login immediately by setting 'PermitRootLogin no' in $SSHD_CONFIG")
fi

if [ "$(check_satisfied 'Password Authentication')" = "No" ]; then
    recommendations+=("CRITICAL: Disable password authentication and use key-based authentication only")
fi

if [ "$(check_satisfied 'Key Permissions')" = "No" ]; then
    recommendations+=("CRITICAL: Fix SSH key permissions - private keys should be 600, public keys 644")
fi

if [ "$(check_satisfied 'Key Strength')" = "No" ]; then
    recommendations+=("CRITICAL: Upgrade RSA keys to at least 3072 bits or switch to ED25519")
fi

if [ "$(check_satisfied 'Strong Algorithms')" = "No" ]; then
    recommendations+=("CRITICAL: Remove weak cryptographic algorithms (MD5, SHA1)")
fi

if [ "$(check_satisfied 'Fail2ban')" = "No" ]; then
    recommendations+=("HIGH: Install and configure fail2ban to protect against brute force attacks")
fi

if [ "$ssh_port" = "22" ]; then
    recommendations+=("MEDIUM: Consider changing default SSH port from 22 to a non-standard port")
fi

if [ "$(check_satisfied 'Crypto Settings')" = "No" ]; then
    recommendations+=("MEDIUM: Configure strong cipher suites in $SSHD_CONFIG")
fi

if [ "$(check_satisfied 'File Ownership')" = "No" ]; then
    recommendations+=("HIGH: Fix SSH file ownership - should be root:root")
fi

if [ "$(check_satisfied 'Directory Permissions')" = "No" ]; then
    recommendations+=("HIGH: Fix SSH directory permissions - should be 755 for /etc/ssh")
fi

# Display top 4 most critical recommendations
echo -e "\nTop Priority Recommendations:"
count=0
for rec in "${recommendations[@]}"; do
    if [ $count -lt 4 ]; then
        echo "$(($count + 1)). $rec"
        count=$((count + 1))
    else
        break
    fi
done

# Add this before the final summary
echo -e "\n${BLUE}=== Cleaning Up ===${NC}"
if [ "$SSH_WAS_STOPPED" = "true" ]; then
    echo -e "Restoring initial SSH server state..."
fi

# Final summary
echo -e "\n${BLUE}=== Audit Complete ===${NC}"
echo "Full audit log available at: $LOG_FILE"
log_message "INFO" "SSH security audit completed with summary table and recommendations"

# Add new alternative checks
echo -e "\n${YELLOW}Additional Security Checks:${NC}"

# Check SSH process
if pgrep -f sshd >/dev/null; then
    echo -e "${GREEN}✓${NC} SSH daemon is running"
    # Get process details
    ps -ef | grep sshd | grep -v grep
else
    echo -e "${RED}✗${NC} SSH daemon is not running"
fi

# Check SSH service status
if systemctl is-active --quiet sshd; then
    echo -e "${GREEN}✓${NC} SSH service is active"
    systemctl status sshd | grep "Active:"
else
    echo -e "${RED}✗${NC} SSH service is not active"
fi

# Check SSH port status
if command -v netstat >/dev/null 2>&1; then
    if netstat -tuln | grep -q ":$ssh_port"; then
        echo -e "${GREEN}✓${NC} SSH port $ssh_port is open and listening"
    else
        echo -e "${RED}✗${NC} SSH port $ssh_port is not listening"
    fi
elif command -v ss >/dev/null 2>&1; then
    if ss -tuln | grep -q ":$ssh_port"; then
        echo -e "${GREEN}✓${NC} SSH port $ssh_port is open and listening"
    else
        echo -e "${RED}✗${NC} SSH port $ssh_port is not listening"
    fi
fi

# Check SSH keys
echo -e "\nChecking SSH host keys:"
if [ -d "$SSH_DIR" ]; then
    key_count=$(find "$SSH_DIR" -name 'ssh_host_*_key' | wc -l)
    if [ "$key_count" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} Found $key_count SSH host keys"
        find "$SSH_DIR" -name 'ssh_host_*_key.pub' -exec ssh-keygen -lf {} \;
    else
        echo -e "${RED}✗${NC} No SSH host keys found"
    fi
fi