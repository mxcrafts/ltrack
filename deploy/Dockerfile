FROM golang:1.23-bookworm AS builder

# Add LLVM official repository
RUN apt-get update && apt-get install -y wget gnupg2 && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm main" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y \
    clang-14 \
    llvm-14 \
    libelf-dev \
    make \
    gcc \
    libc6-dev \
    linux-headers-generic \
    pkg-config \
    m4 \
    libpcap-dev \
    libbpf-dev \
    linux-libc-dev \
    libcap-ng-dev \
    libbfd-dev \
    libcap-dev \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

# Create header file soft link and llvm tool links
RUN ln -sf /usr/include/asm-generic/ /usr/include/asm && \
    ln -sf /usr/bin/llvm-strip-14 /usr/bin/llvm-strip && \
    ln -sf /usr/bin/clang-14 /usr/bin/clang

# Set environment variables for eBPF
ENV BPF_CLANG=clang
ENV BPF_CFLAGS="-O2 -g -Wall -Werror"
ENV LLVM_STRIP=llvm-strip

WORKDIR /build
COPY . .

# Build the application
RUN make generate && make

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    libpcap0.8 \
    libbpf1 \
    linux-headers-generic \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary and default config
COPY --from=builder /build/bin/mxtrack /app/bin/mxtrack
COPY --from=builder /build/policy.toml /app/policy.toml

# Create necessary directories
RUN mkdir -p /var/log/mxtrack /sys/fs/bpf

# Add entrypoint script
COPY deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]