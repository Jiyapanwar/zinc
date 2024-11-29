#!/bin/bash

# Colors for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Security checks directory
SECURITY_CHECKS_DIR="../../../securityChecks"

# Function to display the header
display_header() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}     ZINC Security Scanner      ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

# Function to get available security check scripts
get_available_scripts() {
    local scripts=()
    # Read all .sh files from the security checks directory
    while IFS= read -r -d '' file; do
        # Get the script name without path and extension
        script_name=$(basename "$file" .sh)
        # Convert to title case and replace underscores with spaces
        display_name=$(echo "$script_name" | sed -e 's/_/ /g' -e 's/\b\(.\)/\u\1/g')
        scripts+=("$script_name:$display_name")
    done < <(find "$SECURITY_CHECKS_DIR" -name "*.sh" -print0)
    echo "${scripts[@]}"
}

# Function to display the menu
display_menu() {
    local scripts=($1)
    echo -e "${YELLOW}Available Security Checks:${NC}"
    echo ""
    
    local i=1
    for script in "${scripts[@]}"; do
        IFS=':' read -r script_name display_name <<< "$script"
        echo -e "$i) ${GREEN}$display_name${NC}"
        ((i++))
    done
    
    echo -e "$i) ${RED}Exit${NC}"
    echo ""
    echo -e "Please select an option (1-$i):"
}

# Function to run a security check script
run_security_check() {
    local script_path="$1"
    
    if [ -f "$script_path" ]; then
        echo -e "${BLUE}Running security check...${NC}"
        echo ""
        # Make sure the script is executable
        chmod +x "$script_path"
        # Run the script
        bash "$script_path"
        echo ""
        echo -e "${GREEN}Security check completed.${NC}"
        echo -e "Press Enter to continue..."
        read -r
    else
        echo -e "${RED}Error: Security check script not found!${NC}"
        echo -e "Press Enter to continue..."
        read -r
    fi
}

# Main loop
while true; do
    display_header
    
    # Get available scripts
    IFS=' ' read -r -a scripts <<< "$(get_available_scripts)"
    
    # Display menu
    display_menu "${scripts[*]}"
    
    # Read user input
    read -r choice
    
    # Validate input
    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Invalid input. Please enter a number.${NC}"
        sleep 2
        continue
    fi
    
    # Exit if user chose the last option
    if [ "$choice" -eq ${#scripts[@]} ]; then
        echo -e "${BLUE}Thank you for using ZINC Security Scanner!${NC}"
        exit 0
    fi
    
    # Run selected security check
    if [ "$choice" -ge 1 ] && [ "$choice" -le ${#scripts[@]} ]; then
        selected_script=${scripts[$((choice-1))]}
        IFS=':' read -r script_name display_name <<< "$selected_script"
        script_path="$SECURITY_CHECKS_DIR/${script_name}.sh"
        run_security_check "$script_path"
    else
        echo -e "${RED}Invalid option. Please try again.${NC}"
        sleep 2
    fi
done
