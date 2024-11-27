#!/bin/bash

# Firewall Security Audit Script
# Based on firewallPlan.txt checklist
# For Debian-based Linux systems

# Colors for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging setup
LOG_FILE="/var/log/firewall_security_audit.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    echo -e "${TIMESTAMP} [$level] $message" | tee -a "$LOG_FILE"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check UFW installation and status
check_ufw_status() {
    echo -e "\n${YELLOW}Checking UFW Status:${NC}"
    
    if command_exists ufw; then
        echo -e "${GREEN}✓${NC} UFW is installed"
        log_message "INFO" "UFW is installed"
        
        if systemctl is-active --quiet ufw; then
            echo -e "${GREEN}✓${NC} UFW service is active"
            log_message "INFO" "UFW service is active"
            
            if ufw status | grep -q "Status: active"; then
                echo -e "${GREEN}✓${NC} UFW firewall is enabled"
                log_message "INFO" "UFW firewall is enabled"
            else
                echo -e "${RED}✗${NC} UFW firewall is installed but not enabled"
                log_message "WARNING" "UFW firewall is installed but not enabled"
            fi
        else
            echo -e "${RED}✗${NC} UFW service is not active"
            log_message "WARNING" "UFW service is not active"
        fi
    else
        echo -e "${RED}✗${NC} UFW is not installed"
        log_message "WARNING" "UFW is not installed"
    fi
}

# Function to check IPTables status
check_iptables_status() {
    echo -e "\n${YELLOW}Checking IPTables Status:${NC}"
    
    if command_exists iptables; then
        echo -e "${GREEN}✓${NC} IPTables is installed"
        log_message "INFO" "IPTables is installed"
        
        # Check default policies
        echo -e "\nDefault Chain Policies:"
        for chain in INPUT OUTPUT FORWARD; do
            policy=$(iptables -L $chain | head -n1 | awk '{print $4}')
            if [ "$policy" = "DROP" ] || [ "$policy" = "REJECT" ]; then
                echo -e "${GREEN}✓${NC} $chain chain policy is restrictive: $policy"
                log_message "INFO" "$chain chain policy is restrictive: $policy"
            else
                echo -e "${RED}✗${NC} $chain chain policy is permissive: $policy"
                log_message "WARNING" "$chain chain policy is permissive: $policy"
            fi
        done
    else
        echo -e "${RED}✗${NC} IPTables is not installed"
        log_message "WARNING" "IPTables is not installed"
    fi
}

# Function to check rule configuration
check_rule_configuration() {
    echo -e "\n${YELLOW}Checking Firewall Rules Configuration:${NC}"
    
    # Check UFW rules if installed
    if command_exists ufw; then
        echo -e "\nUFW Rules:"
        ufw status numbered | grep -v "Status:"
        
        # Check critical ports
        local critical_ports=(22 80 443 3306)
        local critical_services=("SSH" "HTTP" "HTTPS" "MySQL")
        
        echo -e "\nCritical Port Status:"
        for i in "${!critical_ports[@]}"; do
            if ufw status | grep -q "${critical_ports[$i]}"; then
                echo -e "${GREEN}✓${NC} ${critical_services[$i]} (${critical_ports[$i]}) is configured"
                log_message "INFO" "${critical_services[$i]} port ${critical_ports[$i]} is configured"
            else
                echo -e "${YELLOW}⚠${NC} ${critical_services[$i]} (${critical_ports[$i]}) not found in rules"
                log_message "WARNING" "${critical_services[$i]} port ${critical_ports[$i]} not found in rules"
            fi
        done
    fi
    
    # Check IPTables rules if installed
    if command_exists iptables; then
        echo -e "\nIPTables Rules:"
        iptables -L -n -v
        
        # Check for common security rules
        if iptables -L -n | grep -q "state RELATED,ESTABLISHED"; then
            echo -e "${GREEN}✓${NC} ESTABLISHED,RELATED connections allowed"
        else
            echo -e "${RED}✗${NC} No rule for ESTABLISHED,RELATED connections"
        fi
    fi
}

# Function to check network security policies
check_network_policies() {
    echo -e "\n${YELLOW}Checking Network Security Policies:${NC}"
    
    # Check for rate limiting rules
    if command_exists iptables; then
        if iptables -L -n | grep -q "limit"; then
            echo -e "${GREEN}✓${NC} Rate limiting rules are configured"
            log_message "INFO" "Rate limiting rules are configured"
        else
            echo -e "${YELLOW}⚠${NC} No rate limiting rules found"
            log_message "WARNING" "No rate limiting rules found"
        fi
    fi
    
    # Check NAT configuration
    if iptables -t nat -L -n 2>/dev/null | grep -q "MASQUERADE\|DNAT\|SNAT"; then
        echo -e "${GREEN}✓${NC} NAT rules are configured"
        echo -e "\nNAT Configuration:"
        iptables -t nat -L -n -v
    else
        echo -e "${YELLOW}⚠${NC} No NAT rules found"
    fi
}

# Function to check logging configuration
check_logging_configuration() {
    echo -e "\n${YELLOW}Checking Logging Configuration:${NC}"
    
    # Check UFW logging
    if command_exists ufw; then
        if ufw status verbose | grep -q "Logging: on"; then
            echo -e "${GREEN}✓${NC} UFW logging is enabled"
            log_message "INFO" "UFW logging is enabled"
        else
            echo -e "${RED}✗${NC} UFW logging is disabled"
            log_message "WARNING" "UFW logging is disabled"
        fi
    fi
    
    # Check IPTables logging
    if command_exists iptables; then
        if iptables -L -n | grep -q "LOG"; then
            echo -e "${GREEN}✓${NC} IPTables logging rules exist"
            log_message "INFO" "IPTables logging rules exist"
        else
            echo -e "${YELLOW}⚠${NC} No IPTables logging rules found"
            log_message "WARNING" "No IPTables logging rules found"
        fi
    fi
    
    # Check connection tracking
    if [ -f "/proc/sys/net/netfilter/nf_conntrack_max" ]; then
        local max_conn=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
        echo -e "${GREEN}✓${NC} Connection tracking enabled (Max: $max_conn)"
        log_message "INFO" "Connection tracking enabled with max connections: $max_conn"
    else
        echo -e "${YELLOW}⚠${NC} Connection tracking not enabled"
        log_message "WARNING" "Connection tracking not enabled"
    fi
}

# Function to check security best practices
check_security_best_practices() {
    echo -e "\n${YELLOW}Checking Security Best Practices:${NC}"
    
    # Check reverse path filtering
    local rpf_value=$(sysctl -n net.ipv4.conf.all.rp_filter)
    if [ "$rpf_value" = "1" ]; then
        echo -e "${GREEN}✓${NC} Reverse path filtering is enabled"
        log_message "INFO" "Reverse path filtering is enabled"
    else
        echo -e "${RED}✗${NC} Reverse path filtering is disabled"
        log_message "WARNING" "Reverse path filtering is disabled"
    fi
    
    # Check invalid packet handling
    if iptables -L -n | grep -q "DROP.*invalid"; then
        echo -e "${GREEN}✓${NC} Invalid packet dropping is configured"
    else
        echo -e "${RED}✗${NC} No rules for invalid packet dropping"
    fi
    
    # Check SYN flood protection
    local synflood_value=$(sysctl -n net.ipv4.tcp_syncookies)
    if [ "$synflood_value" = "1" ]; then
        echo -e "${GREEN}✓${NC} SYN flood protection is enabled"
    else
        echo -e "${RED}✗${NC} SYN flood protection is disabled"
    fi
}

# Function to generate recommendations
generate_recommendations() {
    echo -e "\n${BLUE}=== Security Recommendations ===${NC}"
    local recommendations=()
    
    # Check UFW status
    if ! command_exists ufw; then
        recommendations+=("CRITICAL: Install UFW firewall: sudo apt-get install ufw")
    elif ! ufw status | grep -q "Status: active"; then
        recommendations+=("CRITICAL: Enable UFW firewall: sudo ufw enable")
    fi
    
    # Check default policies
    if command_exists iptables; then
        if ! iptables -L INPUT | head -n1 | grep -q "DROP\|REJECT"; then
            recommendations+=("HIGH: Set default INPUT policy to DROP")
        fi
    fi
    
    # Check logging
    if command_exists ufw && ! ufw status verbose | grep -q "Logging: on"; then
        recommendations+=("MEDIUM: Enable UFW logging: sudo ufw logging on")
    fi
    
    # Check connection tracking
    if [ ! -f "/proc/sys/net/netfilter/nf_conntrack_max" ]; then
        recommendations+=("MEDIUM: Enable connection tracking module")
    fi
    
    # Display recommendations
    if [ ${#recommendations[@]} -eq 0 ]; then
        echo -e "${GREEN}No critical recommendations found.${NC}"
    else
        for i in "${!recommendations[@]}"; do
            echo -e "$((i+1)). ${recommendations[$i]}"
        done
    fi
}

# Function to get threat level
get_threat_level() {
    local check=$1
    case $check in
        "UFW Status") echo "A";;
        "Default Policies") echo "A";;
        "Critical Ports") echo "A";;
        "Rate Limiting") echo "B";;
        "NAT Configuration") echo "B";;
        "Logging Status") echo "B";;
        "Connection Tracking") echo "B";;
        "Reverse Path Filter") echo "A";;
        "Invalid Packets") echo "A";;
        "SYN Flood Protection") echo "A";;
        "ESTABLISHED Rules") echo "A";;
        "IPTables Logging") echo "B";;
        "Service Status") echo "A";;
        "Custom Chains") echo "C";;
        "Rule Conflicts") echo "B";;
        *) echo "C";;
    esac
}

# Function to check if requirement is satisfied
check_satisfied() {
    local check=$1
    case $check in
        "UFW Status")
            command_exists ufw && ufw status | grep -q "Status: active" && echo "Yes" || echo "No"
            ;;
        "Default Policies")
            if command_exists iptables; then
                iptables -L INPUT | head -n1 | grep -q "DROP\|REJECT" && echo "Yes" || echo "No"
            else
                echo "N/A"
            fi
            ;;
        "Critical Ports")
            if command_exists ufw; then
                ufw status | grep -qE "22|80|443" && echo "Yes" || echo "No"
            else
                echo "N/A"
            fi
            ;;
        "Rate Limiting")
            command_exists iptables && iptables -L -n | grep -q "limit" && echo "Yes" || echo "No"
            ;;
        "NAT Configuration")
            command_exists iptables && iptables -t nat -L -n 2>/dev/null | grep -q "MASQUERADE\|DNAT\|SNAT" && echo "Yes" || echo "No"
            ;;
        "Logging Status")
            if command_exists ufw; then
                ufw status verbose | grep -q "Logging: on" && echo "Yes" || echo "No"
            else
                echo "N/A"
            fi
            ;;
        "Connection Tracking")
            [ -f "/proc/sys/net/netfilter/nf_conntrack_max" ] && echo "Yes" || echo "No"
            ;;
        "Reverse Path Filter")
            [ "$(sysctl -n net.ipv4.conf.all.rp_filter)" = "1" ] && echo "Yes" || echo "No"
            ;;
        "Invalid Packets")
            command_exists iptables && iptables -L -n | grep -q "DROP.*invalid" && echo "Yes" || echo "No"
            ;;
        "SYN Flood Protection")
            [ "$(sysctl -n net.ipv4.tcp_syncookies)" = "1" ] && echo "Yes" || echo "No"
            ;;
        "ESTABLISHED Rules")
            command_exists iptables && iptables -L -n | grep -q "state RELATED,ESTABLISHED" && echo "Yes" || echo "No"
            ;;
        "IPTables Logging")
            command_exists iptables && iptables -L -n | grep -q "LOG" && echo "Yes" || echo "No"
            ;;
        "Service Status")
            systemctl is-active --quiet ufw && echo "Yes" || echo "No"
            ;;
        "Custom Chains")
            command_exists iptables && iptables -L -n | grep -q "Chain" && [ "$(iptables -L -n | grep "Chain" | wc -l)" -gt 3 ] && echo "Yes" || echo "No"
            ;;
        "Rule Conflicts")
            if command_exists ufw; then
                ufw status numbered | grep -q "DENY.*ALLOW\|ALLOW.*DENY" && echo "No" || echo "Yes"
            else
                echo "N/A"
            fi
            ;;
        *)
            echo "Unknown"
            ;;
    esac
}

# Function to backup firewall rules
backup_firewall_rules() {
    local backup_dir="/etc/firewall/backups"
    local backup_file="${backup_dir}/firewall_rules_$(date +%Y%m%d_%H%M%S).bak"
    
    # Create backup directory if it doesn't exist
    if [ ! -d "$backup_dir" ]; then
        mkdir -p "$backup_dir"
        chmod 700 "$backup_dir"
    fi
    
    echo -e "\n${BLUE}Backing up Firewall Rules${NC}"
    
    # Backup UFW rules if available
    if command_exists ufw; then
        ufw status numbered > "${backup_file}_ufw"
        echo -e "${GREEN}✓${NC} UFW rules backed up to ${backup_file}_ufw"
    fi
    
    # Backup IPTables rules if available
    if command_exists iptables; then
        iptables-save > "${backup_file}_iptables"
        echo -e "${GREEN}✓${NC} IPTables rules backed up to ${backup_file}_iptables"
    fi
    
    # Backup nftables rules if available
    if command_exists nft; then
        nft list ruleset > "${backup_file}_nftables"
        echo -e "${GREEN}✓${NC} nftables rules backed up to ${backup_file}_nftables"
    fi
    
    log_message "INFO" "Firewall rules backed up to ${backup_dir}"
}

# Function to restore firewall rules
restore_firewall_rules() {
    local backup_dir="/etc/firewall/backups"
    
    if [ ! -d "$backup_dir" ]; then
        echo -e "${RED}No backup directory found${NC}"
        return 1
    fi
    
    # List available backups
    echo -e "\n${BLUE}Available Backups:${NC}"
    ls -lt "$backup_dir" | grep -v '^total'
    
    echo -e "\nEnter backup filename to restore (or 'q' to quit):"
    read -r backup_name
    
    if [ "$backup_name" = "q" ]; then
        return 0
    fi
    
    if [ -f "${backup_dir}/${backup_name}" ]; then
        case "$backup_name" in
            *_ufw)
                ufw --force reset
                while IFS= read -r rule; do
                    [[ "$rule" =~ \[.*\] ]] && ufw add "${rule#*] }"
                done < "${backup_dir}/${backup_name}"
                ;;
            *_iptables)
                iptables-restore < "${backup_dir}/${backup_name}"
                ;;
            *_nftables)
                nft -f "${backup_dir}/${backup_name}"
                ;;
            *)
                echo -e "${RED}Unknown backup type${NC}"
                return 1
                ;;
        esac
        echo -e "${GREEN}✓${NC} Firewall rules restored from ${backup_name}"
        log_message "INFO" "Firewall rules restored from ${backup_name}"
    else
        echo -e "${RED}Backup file not found${NC}"
        return 1
    fi
}

# Function for detailed rule conflict analysis
analyze_rule_conflicts() {
    echo -e "\n${YELLOW}Analyzing Rule Conflicts:${NC}"
    
    if command_exists ufw; then
        local rules=$(ufw status numbered)
        local conflicts=()
        
        # Check for conflicting allow/deny rules
        while IFS= read -r line1; do
            while IFS= read -r line2; do
                if [[ "$line1" =~ ALLOW && "$line2" =~ DENY ]]; then
                    # Extract port and protocol
                    local port1=$(echo "$line1" | grep -oE '[0-9]+(/[a-z]+)?')
                    local port2=$(echo "$line2" | grep -oE '[0-9]+(/[a-z]+)?')
                    if [ "$port1" = "$port2" ]; then
                        conflicts+=("Conflict found: ALLOW and DENY rules for port $port1")
                    fi
                fi
            done <<< "$rules"
        done <<< "$rules"
        
        # Check for redundant rules
        local redundant=$(echo "$rules" | sort | uniq -d)
        
        if [ ${#conflicts[@]} -gt 0 ]; then
            echo -e "${RED}Rule Conflicts Found:${NC}"
            printf '%s\n' "${conflicts[@]}"
        fi
        
        if [ -n "$redundant" ]; then
            echo -e "${YELLOW}Redundant Rules Found:${NC}"
            echo "$redundant"
        fi
    fi
}

# Function to check nftables
check_nftables() {
    echo -e "\n${YELLOW}Checking nftables Status:${NC}"
    
    if command_exists nft; then
        echo -e "${GREEN}✓${NC} nftables is installed"
        
        # Check if nftables service is running
        if systemctl is-active --quiet nftables; then
            echo -e "${GREEN}✓${NC} nftables service is active"
        else
            echo -e "${RED}✗${NC} nftables service is not active"
        fi
        
        # List current ruleset
        echo -e "\nCurrent nftables ruleset:"
        nft list ruleset
        
        # Check for basic security rules
        if nft list ruleset | grep -q "ct state established,related accept"; then
            echo -e "${GREEN}✓${NC} State tracking rules are configured"
        else
            echo -e "${RED}✗${NC} Missing state tracking rules"
        fi
    else
        echo -e "${YELLOW}⚠${NC} nftables is not installed"
    fi
}

# Function for periodic monitoring
setup_periodic_monitoring() {
    local monitor_script="/usr/local/bin/firewall_monitor.sh"
    local cron_file="/etc/cron.d/firewall_monitor"
    
    # Create monitoring script
    cat > "$monitor_script" << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/firewall_monitor.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# Check firewall status
if command -v ufw >/dev/null 2>&1; then
    ufw status > "$LOG_FILE"
fi

# Check for suspicious activities
if [ -f "/var/log/ufw.log" ]; then
    echo "Recent Blocked Connections (Last Hour):" >> "$LOG_FILE"
    grep "$(date -d '1 hour ago' +'%b %d %H')" /var/log/ufw.log | grep "BLOCK" >> "$LOG_FILE"
fi

# Check connection tracking
if [ -f "/proc/sys/net/netfilter/nf_conntrack_count" ]; then
    echo "Current Connections: $(cat /proc/sys/net/netfilter/nf_conntrack_count)" >> "$LOG_FILE"
fi

# Alert on significant changes
if [ -f "/var/log/firewall_monitor.log.old" ]; then
    changes=$(diff /var/log/firewall_monitor.log.old "$LOG_FILE" | grep "^>" | wc -l)
    if [ "$changes" -gt 10 ]; then
        echo "WARNING: Significant changes detected in firewall rules" | \
        mail -s "Firewall Monitor Alert" root
    fi
fi

cp "$LOG_FILE" /var/log/firewall_monitor.log.old
EOF
    
    chmod +x "$monitor_script"
    
    # Create cron job
    echo "*/15 * * * * root $monitor_script" > "$cron_file"
    chmod 644 "$cron_file"
    
    echo -e "${GREEN}✓${NC} Periodic monitoring setup complete"
    echo "Monitor script: $monitor_script"
    echo "Cron job: $cron_file"
    log_message "INFO" "Periodic monitoring setup completed"
}

# Function to print security table
print_security_table() {
    echo -e "\n${BLUE}=== Security Threat Analysis ===${NC}"
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
    checks=("UFW Status" "Default Policies" "Critical Ports" "Rate Limiting" 
            "NAT Configuration" "Logging Status" "Connection Tracking" 
            "Reverse Path Filter" "Invalid Packets" "SYN Flood Protection" 
            "ESTABLISHED Rules" "IPTables Logging" "Service Status" 
            "Custom Chains" "Rule Conflicts")
    
    # Print table rows
    for check in "${checks[@]}"; do
        threat_level=$(get_threat_level "$check")
        satisfied=$(check_satisfied "$check")
        printf "%-25s | %-15s | %-10s\n" "$check" "$threat_level" "$satisfied"
    done
    
    printf "%.s-" {1..55}
    printf "\n"
}

# Main script execution
echo -e "${BLUE}=== Firewall Security Audit ===${NC}"
echo -e "Started at: ${TIMESTAMP}\n"
log_message "INFO" "Starting firewall security audit"

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root${NC}"
    log_message "ERROR" "Script must be run as root"
    exit 1
fi

# Main menu
show_menu() {
    echo -e "\n${BLUE}Firewall Security Management${NC}"
    echo "1. Run Security Audit"
    echo "2. Backup Firewall Rules"
    echo "3. Restore Firewall Rules"
    echo "4. Analyze Rule Conflicts"
    echo "5. Check nftables Status"
    echo "6. Setup Periodic Monitoring"
    echo "7. Exit"
    echo -n "Select an option: "
    read -r choice
    
    case $choice in
        1)
            run_security_audit
            ;;
        2)
            backup_firewall_rules
            ;;
        3)
            restore_firewall_rules
            ;;
        4)
            analyze_rule_conflicts
            ;;
        5)
            check_nftables
            ;;
        6)
            setup_periodic_monitoring
            ;;
        7)
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# Function to run the security audit
run_security_audit() {
    check_ufw_status
    check_iptables_status
    check_rule_configuration
    check_network_policies
    check_logging_configuration
    check_security_best_practices
    check_nftables
    
    # Print security threat table
    print_security_table
    
    # Generate recommendations
    generate_recommendations
}

# Show menu and handle user input
while true; do
    show_menu
done 