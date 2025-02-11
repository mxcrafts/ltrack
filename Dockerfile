FROM golang:1.21-bullseye as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    make \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build the application
RUN make generate && make build

FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary and necessary files
COPY --from=builder /app/bin/mxtrack /app/bin/mxtrack
COPY --from=builder /app/policy.toml /app/policy.toml

# Create log directory
RUN mkdir -p /var/log/mxtrack

ENTRYPOINT ["/app/bin/mxtrack"]
CMD ["--config", "/app/policy.toml"] 