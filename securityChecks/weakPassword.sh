#!/bin/bash

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to suggest a stronger password
suggest_password() {
    local username=$1
    echo -e "${YELLOW}For user '$username', consider using a stronger password like:${NC}"
    echo "$(openssl rand -base64 16 | tr -d '=')" # Generates a random password
}

# Function to check password strength
check_password_strength() {
    local password=$1
    local strength="weak" # Default strength

    # Check password length
    if [[ ${#password} -lt 8 ]]; then
        strength="weak"
    elif [[ ${#password} -ge 8 && ${#password} -lt 12 ]]; then
        strength="medium"
    else
        strength="strong"
    fi

    # Check for password complexity
    if [[ $password =~ [a-z] && $password =~ [A-Z] && $password =~ [0-9] ]]; then
        # Password contains at least one lowercase, one uppercase, and one digit
        if [[ $strength == "weak" ]]; then
            strength="medium"
        elif [[ $strength == "medium" ]]; then
            strength="strong"
        fi
    fi

    echo "$strength"
}

# Header for output
echo -e "${BLUE}Weak Password Detection Report${NC}"
echo "==============================="
echo ""

# Get all users from /etc/passwd
while IFS=: read -r username _; do
    # Skip system users (UID < 1000)
    if [[ $(id -u "$username" 2>/dev/null) -lt 1000 ]]; then
        continue
    fi

    # Simulating password retrieval (in reality, you cannot check a password hash directly)
    # For demonstration purposes, let's assume the password is the username for checking strength
    password="${username}" # Replace this with actual password retrieval logic if possible

    # Check password strength
    strength=$(check_password_strength "$password")

    case $strength in
        "weak")
            echo -e "${RED}User     '$username' has a weak password.${NC}"
            suggest_password "$username"
            ;;
        "medium")
            echo -e "${YELLOW}User     '$username' has a medium strength password.${NC}"
            echo "Consider using a stronger password."
            suggest_password "$username"
            ;;
        "strong")
            echo -e "${GREEN}User     '$username' has a strong password.${NC}"
            ;;
    esac
    echo ""
done < /etc/passwd  # Read from /etc/passwd to get all users

echo "==============================="
echo -e "${BLUE}End of Report${NC}"