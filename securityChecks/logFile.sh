#!/bin/bash


# Log File Analysis Script
# Enhanced with additional features for security auditing


# Colors for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color


# Logging setup
LOG_FILE="/var/log/auth.log"
OUTPUT_DIR="./security_reports"
mkdir -p "$OUTPUT_DIR"
LOG_OUTPUT="$OUTPUT_DIR/log_analysis.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")


# Function to log messages
log_message() {
    local level=$1
    local message=$2
    echo -e "${TIMESTAMP} [$level] $message" | tee -a "$LOG_OUTPUT"
}


# Banner
echo "==========================================="
echo "          Log File Analysis                "
echo "==========================================="
echo "Analyzing log file: $LOG_FILE"
echo "Reports will be saved in: $OUTPUT_DIR"


# Ensure necessary tools are installed
REQUIRED_TOOLS=(tripwire snort ufw fail2ban unattended-upgrades mailutils)
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "Installing $tool..."
        sudo apt-get update && sudo apt-get install -y $tool
        log_message "INFO" "$tool installed."
    fi
done


# Initialize Tripwire
if [[ ! -f /etc/tripwire/tw.cfg ]]; then
    echo "Initializing Tripwire..."
    sudo tripwire --init
    log_message "INFO" "Tripwire initialized."
fi



# Check if log file exists
if [[ ! -f "$LOG_FILE" ]]; then
    echo "Log file $LOG_FILE not found! Ensure you are running this on a system with auth.log."
    exit 1
fi


# Extract and analyze failed login attempts
echo "Extracting failed login attempts..."
grep "Failed password" "$LOG_FILE" > "$OUTPUT_DIR/failed_logins.txt"

echo "Counting failed login attempts per IP..."
awk '{print $11}' "$OUTPUT_DIR/failed_logins.txt" | sort | uniq -c | sort -nr > "$OUTPUT_DIR/failed_attempts_by_ip.txt"


# Block brute force IPs
echo "Blocking IPs with excessive failed login attempts..."
BRUTE_FORCE_THRESHOLD=5
while read -r line; do
    ATTEMPTS=$(echo "$line" | awk '{print $1}')
    IP=$(echo "$line" | awk '{print $2}')
    if [[ "$ATTEMPTS" -gt "$BRUTE_FORCE_THRESHOLD" ]]; then
        echo "Blocking IP $IP with $ATTEMPTS failed attempts..."
        sudo ufw deny from $IP
        echo "$(date): Blocked $IP after $ATTEMPTS failed attempts" >> "$OUTPUT_DIR/brute_force_alerts.txt"
        log_message "WARNING" "Blocked IP $IP after $ATTEMPTS failed attempts."
    fi
done < "$OUTPUT_DIR/failed_attempts_by_ip.txt"


# Disable root login via SSH
echo "Ensuring root login via SSH is disabled..."
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
log_message "INFO" "Root login via SSH disabled."


# Extract successful root logins
echo "Extracting successful root logins..."
grep "Accepted" "$LOG_FILE" | grep "root" > "$OUTPUT_DIR/successful_root_logins.txt"


# Extract invalid user login attempts
echo "Extracting invalid user login attempts..."
grep "Invalid user" "$LOG_FILE" > "$OUTPUT_DIR/invalid_user_attempts.txt"


# Perform Tripwire integrity check
echo "Running Tripwire file integrity check..."
sudo tripwire --check > "$OUTPUT_DIR/tripwire_report.txt"
log_message "INFO" "Tripwire integrity check completed."


# Review sudo access for users
echo "Reviewing sudo access for users..."
sudo grep -E -i 'sudo' /etc/group > "$OUTPUT_DIR/sudo_users.txt"


# Log rotation review
echo "Reviewing log rotation configuration..."
sudo cat /etc/logrotate.conf > "$OUTPUT_DIR/logrotate_config.txt"


# Check for known vulnerabilities
echo "Checking for known vulnerabilities..."
VULNERABILITY_CHECKS=("apt-get update" "apt-get upgrade" "apt-get dist-upgrade")
for check in "${VULNERABILITY_CHECKS[@]}"; do
    echo "Running: $check"
    eval "$check"
    log_message "INFO" "$check executed."
done


# Configure Fail2Ban
echo "Ensuring Fail2Ban is active..."
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
log_message "INFO" "Fail2Ban configured and started."


# Configure automatic updates
echo "Enabling automatic updates..."
sudo dpkg-reconfigure --priority=low unattended-upgrades
sudo systemctl enable unattended-upgrades
sudo systemctl start unattended-upgrades
log_message "INFO" "Automatic updates enabled."


# Centralized logging placeholder
echo "Setting up centralized logging with ELK Stack..."

# Instructions for ELK setup can be included here if ELK is available
log_message "INFO" "Centralized logging setup initiated."


# Email alerts for critical issues
echo "Configuring email alerts for critical log issues..."
EMAIL="admin@example.com"
if [[ -n "$EMAIL" ]]; then
    echo "Critical Issues Detected:" > "$OUTPUT_DIR/critical_issues.txt"
    cat "$OUTPUT_DIR/brute_force_alerts.txt" >> "$OUTPUT_DIR/critical_issues.txt"
    mail -s "Log Analysis Alerts" "$EMAIL" < "$OUTPUT_DIR/critical_issues.txt"
    log_message "INFO" "Email alerts sent to $EMAIL."
fi


# Summarize and finalize
echo "Log Analysis Completed. Summary:"
echo "-------------------------------------------"
echo "Potential Brute Force Attempts:"
cat "$OUTPUT_DIR/brute_force_alerts.txt"
echo
echo "Reports saved in: $OUTPUT_DIR"


# Reload firewall to apply rules
echo "Reloading firewall to ensure rules are applied..."
sudo ufw reload
log_message "INFO" "Firewall reloaded to apply new rules."


# Final log message
log_message "INFO" "Log file analysis script completed successfully."