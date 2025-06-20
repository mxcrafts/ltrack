#!/bin/bash

# Color definition
GREEN='\033[0;32m' 
YELLOW='\033[1;33m'
NC='\033[0m'

# Print colored message
print_step() {
    echo -e "${GREEN}[TEST STEP]${NC} $1"
    # Wait for 2 seconds to ensure eBPF has enough time to capture events
    sleep 2
}

print_command() {
    echo -e "${YELLOW}[COMMAND]${NC} $1"
    # Execute command
    eval $1
    # Wait for 1 second to allow eBPF to complete capture
    sleep 1
}

# Display script start information
echo "====================================="
echo "Exec Monitor Test Script Started"
echo "====================================="

# Test bash commands
print_step "Testing bash command execution"
print_command "bash -c 'echo \"Testing bash execution\"'"
print_command "bash -c 'ls -la /tmp'"

# Test python commands
print_step "Testing python command execution"
print_command "python3 -c 'print(\"Hello from Python\")'"
print_command "python3 -c 'import os; print(\"Python process ID:\", os.getpid())'"

# Test more complex command scenarios
print_step "Testing command execution with arguments"
print_command "bash -c 'echo \"Args test\" > /tmp/args_test.txt'"
print_command "cat /tmp/args_test.txt"
print_command "rm /tmp/args_test.txt"

# Test script execution
print_step "Testing script execution"
print_command "echo '#!/bin/bash\necho \"Script execution test\"' > /tmp/test_script.sh"
print_command "chmod +x /tmp/test_script.sh"
print_command "bash /tmp/test_script.sh"
print_command "rm /tmp/test_script.sh"

# Test with environment variables
print_step "Testing execution with environment variables"
print_command "TEST_ENV_VAR='test_value' bash -c 'echo \"Environment variable: $TEST_ENV_VAR\"'"

print_step "Test completed" 
echo "====================================="
echo "All test operations completed, please check log output"
echo "=====================================" 
