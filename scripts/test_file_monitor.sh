#!/bin/bash

# Test directory configuration
TEST_DIR="/home/lighthouse/test-ltrack"

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
echo "File Monitor Test Script Started"
echo "Test directory: $TEST_DIR"
echo "====================================="

# Ensure test directory exists
mkdir -p $TEST_DIR

# Clear test directory
print_step "Cleaning test directory"
print_command "rm -rf $TEST_DIR/*"

# File operation tests
print_step "Creating test files"
print_command "touch $TEST_DIR/test1.txt"
print_command "echo \"hello\" > $TEST_DIR/test2.txt"

print_step "Creating test directories"
print_command "mkdir $TEST_DIR/testdir1"
print_command "mkdir -p $TEST_DIR/testdir2/subdir"

print_step "Creating files in subdirectories"
print_command "touch $TEST_DIR/testdir1/file1.txt"
print_command "echo \"test content\" > $TEST_DIR/testdir2/file2.txt"

print_step "Moving/renaming files"
print_command "mv $TEST_DIR/test1.txt $TEST_DIR/test1_renamed.txt"
print_command "mv $TEST_DIR/testdir1/file1.txt $TEST_DIR/testdir2/"

print_step "Deleting files"
print_command "rm -v $TEST_DIR/test2.txt"
print_command "rm -v $TEST_DIR/testdir2/file2.txt"

print_step "Deleting directories"
print_command "rmdir -v $TEST_DIR/testdir1"
print_command "rm -rfv $TEST_DIR/testdir2"

print_step "Test completed" 
echo "====================================="
echo "All test operations completed, please check log output"
echo "=====================================" 