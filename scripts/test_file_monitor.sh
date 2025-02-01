#!/bin/bash

# Test directory configuration
TEST_DIR="/home/lighthouse/test-mxtrack"

# Color definition
GREEN='\033[0;32m' 
NC='\033[0m'

# Print colored message
print_step() {
    echo -e "${GREEN}[TEST STEP]${NC} $1"
    # Wait 1 second for observation
    sleep 1
}

# Ensure test directory exists
mkdir -p $TEST_DIR

# Clear test directory
print_step "Clearing test directory"
rm -rf $TEST_DIR/*

# File operation tests
print_step "Creating test files"
touch $TEST_DIR/test1.txt
echo "hello" > $TEST_DIR/test2.txt

print_step "Creating test directories"
mkdir $TEST_DIR/testdir1
mkdir -p $TEST_DIR/testdir2/subdir

print_step "Creating files in subdirectories"
touch $TEST_DIR/testdir1/file1.txt
echo "test content" > $TEST_DIR/testdir2/file2.txt

print_step "Moving/renaming files"
mv $TEST_DIR/test1.txt $TEST_DIR/test1_renamed.txt
mv $TEST_DIR/testdir1/file1.txt $TEST_DIR/testdir2/

print_step "Deleting files"
rm $TEST_DIR/test2.txt
rm $TEST_DIR/testdir2/file2.txt

print_step "Deleting directories"
rmdir $TEST_DIR/testdir1
rm -rf $TEST_DIR/testdir2

print_step "Test completed" 