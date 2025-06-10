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
    # 等待时间延长到2秒，确保eBPF有足够时间捕获事件
    sleep 2
}

print_command() {
    echo -e "${YELLOW}[COMMAND]${NC} $1"
    # 执行命令
    eval $1
    # 等待1秒让eBPF捕获完成
    sleep 1
}

# 显示脚本启动信息
echo "====================================="
echo "文件监控测试脚本开始执行"
echo "测试目录: $TEST_DIR"
echo "====================================="

# Ensure test directory exists
mkdir -p $TEST_DIR

# Clear test directory
print_step "清理测试目录"
print_command "rm -rf $TEST_DIR/*"

# File operation tests
print_step "创建测试文件"
print_command "touch $TEST_DIR/test1.txt"
print_command "echo \"hello\" > $TEST_DIR/test2.txt"

print_step "创建测试目录"
print_command "mkdir $TEST_DIR/testdir1"
print_command "mkdir -p $TEST_DIR/testdir2/subdir"

print_step "在子目录中创建文件"
print_command "touch $TEST_DIR/testdir1/file1.txt"
print_command "echo \"test content\" > $TEST_DIR/testdir2/file2.txt"

print_step "移动/重命名文件"
print_command "mv $TEST_DIR/test1.txt $TEST_DIR/test1_renamed.txt"
print_command "mv $TEST_DIR/testdir1/file1.txt $TEST_DIR/testdir2/"

print_step "删除文件"
print_command "rm -v $TEST_DIR/test2.txt"
print_command "rm -v $TEST_DIR/testdir2/file2.txt"

print_step "删除目录"
print_command "rmdir -v $TEST_DIR/testdir1"
print_command "rm -rfv $TEST_DIR/testdir2"

print_step "测试完成" 
echo "====================================="
echo "所有测试操作已完成，请检查日志输出"
echo "=====================================" 