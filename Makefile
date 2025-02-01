# Project directories
OUTPUT := ../output
VMLINUXH := $(abspath ../vmlinux.h)

# Compiler settings
CC := gcc
CLANG := clang

# Architecture detection
ARCH := $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))
GOARCH := $(ARCH)

# System tools
BPFTOOL := $(shell which bpftool || /bin/false)
BTFFILE := /sys/kernel/btf/vmlinux
DBGVMLINUX := /usr/lib/debug/boot/vmlinux-$(shell uname -r)

# Compilation flags
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -target bpfel \
	-D__TARGET_ARCH_x86 \
	-I$(abspath $(dir $(VMLINUXH))) \
	-I/usr/include/$(shell uname -m)-linux-gnu \
	$(CFLAGS)

# Binary output settings
BINARY_NAME := mxtrack
BINARY_DIR := bin

# Default target
.PHONY: all
all: $(BINARY_NAME)

# Generate vmlinux.h
.PHONY: vmlinuxh
vmlinuxh: $(VMLINUXH)

$(VMLINUXH): | $(OUTPUT)
	@if [ -f $(DBGVMLINUX) ]; then \
		echo "INFO: generating $(VMLINUXH) from $(DBGVMLINUX)"; \
		$(BPFTOOL) btf dump file $(DBGVMLINUX) format c > $(VMLINUXH); \
	elif [ -f $(BTFFILE) ]; then \
		echo "INFO: generating $(VMLINUXH) from $(BTFFILE)"; \
		$(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUXH); \
	else \
		echo "ERROR: no BTF file found"; \
		exit 1; \
	fi

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

$(BINARY_DIR):
	mkdir -p $(BINARY_DIR)

# Generate eBPF code
.PHONY: generate
generate: vmlinuxh
	cd internal && \
	BPF_CLANG="$(CLANG)" \
	BPF_CFLAGS="$(BPF_CFLAGS)" \
	go generate ./...

# Build Go program
.PHONY: $(BINARY_NAME)
$(BINARY_NAME): generate | $(BINARY_DIR)
	go build -buildvcs=false -o $(BINARY_DIR)/$(BINARY_NAME) ./cmd

# Run targets
.PHONY: run
run:
	sudo ./$(BINARY_DIR)/$(BINARY_NAME)

.PHONY: cat
cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(OUTPUT)
	rm -rf $(VMLINUXH)
	rm -rf $(BINARY_DIR)
	rm -f pkg/ebpf/c/*.o