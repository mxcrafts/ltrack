<p align="center">
<a href="https://goreportcard.com/report/github.com/mxcrafts/ltrack">
  <img src="https://goreportcard.com/badge/github.com/mxcrafts/ltrack" alt="Go Report Card">
</a>
<a href="https://godoc.org/github.com/mxcrafts/ltrack">
  <img src="https://godoc.org/github.com/mxcrafts/ltrack?status.svg" alt="GoDoc">
</a>
<a href="LICENSE">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
</a>
</p>


<h3 align="center">
  <div style="display:flex;flex-direction:column;align-items:center;">
    <img src="./brand/logo-light.png" alt="ltrack - Security Observability Framework for ML/AI Model File Loading" width=100px>
    <br />
    <p>ltrack - Security Observability Framework for ML/AI Model File Loading</p>
  </div>
</h3>



<p align="center">
  <a href="README.md"><img alt="README in English" src="https://img.shields.io/badge/English-d9d9d9"></a>
  <a href="docs/README_CN.md"><img alt="简体中文版自述文件" src="https://img.shields.io/badge/简体中文-d9d9d9"></a>
</p>



## Overview

> [!NOTE]
> ltrack is an open-source security observability tool designed to monitor and analyze potential risks during the loading and execution of machine learning (ML) and artificial intelligence (AI) model files. Built with Golang and eBPF (Extended Berkeley Packet Filter), ltrack combines the efficiency of low-level kernel tracing with the robustness of modern systems programming to deliver high-performance, low-overhead monitoring. By focusing on critical system behaviors and configurations, ltrack helps developers, MLOps engineers, and security researchers identify vulnerabilities, unauthorized access, and anomalous activities in ML/AI workflows.

## Technical Highlights

- eBPF-Powered Efficiency
Leverages eBPF to perform lightweight, kernel-level event tracing without requiring kernel modifications. This minimizes runtime overhead (<3% CPU in most cases) while enabling real-time observation of system calls, network traffic, and file operations.

- Golang Performance & Portability
Utilizes Golang's concurrency model and cross-platform capabilities to ensure high-throughput event processing and seamless deployment across Linux distributions.

- Zero-Dependency Monitoring
Avoids reliance on external kernel modules or agents, reducing attack surfaces and operational complexity.

## Features

- 🔍 **File Monitoring**: Monitor file operations (create, delete, modify, etc.) in specified directories
- 🚀 **Process Monitoring**: Track execution of specified commands
- 🌐 **Network Monitoring**: Monitor network activity on specific ports and protocols
- 📝 **Log Management**: Support log rotation, compression, and retention policies
- ⚡ **High Performance**: Low-overhead system monitoring based on eBPF technology
- 🔧 **Configurable**: Flexible monitoring policy configuration via TOML files

## Why ltrack?

- Low Overhead, High Fidelity
eBPF's kernel-space execution eliminates costly context switches, enabling precise tracking of system events without degrading model inference or training performance.

- Real-Time Alerts
Integrates with logging systems (e.g., Elasticsearch, Prometheus) for proactive threat response.

- Extensible Architecture
Supports plugins for custom detectors and integrations, with Golang's static binary packaging simplifying deployment.

## Use Cases

- MLOps Pipelines: Enhance security in CI/CD workflows by auditing model deployment processes.

- Research Environments: Safeguard experimental models and datasets from unintended access or tampering.

- Compliance: Meet regulatory requirements (e.g., GDPR, HIPAA) by enforcing strict access controls and audit trails.

## Quick Start

### Docker Images

```bash
docker run -d \
  --name ltrack \
  --privileged \
  --pid host \
  --network host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /proc:/proc \
  -v /lib/modules:/lib/modules:ro \
  -v ltrack_logs:/var/log/ltrack \
  -v <path>/policy.toml:/app/external-config/policy.toml:ro \
  -e LTRACK_LOG_LEVEL=info \
  -e LTRACK_LOG_FORMAT=json \
  mxcrafts/ltrack:latest
```

### Build a local docker image

```bash
cd deploy

# Using latest version
docker-compose up -d
```

### Build from source

#### Prerequisites

- Linux kernel version >= 4.18
- Go version >= 1.21
- LLVM/Clang 11+

#### Installation

```bash
# build from source
git clone https://github.com/mxcrafts/ltrack.git
cd ltrack
make && LTRACK_LOG_LEVEL=info LTRACK_LOG_FORMAT=json ./bin/ltrack ./bin/ltrack --config policy.toml
```

### Configuration

### Command Line Options

```bash
# Run with default configuration file (policy.toml)
LTRACK_LOG_LEVEL=info LTRACK_LOG_FORMAT=json ./bin/ltrack

# Run with specified configuration file
LTRACK_LOG_LEVEL=info LTRACK_LOG_FORMAT=json ./bin/ltrack --config /path/to/config.toml
```

### Log Level Configuration

The log level can be configured in two ways:

1. Environment Variable (Highest Priority):
```bash
# Set log level via environment variable
export LTRACK_LOG_LEVEL=debug  # Options: debug, info, warn, error
export LTRACK_LOG_FORMAT=json  # Options: json, text

# Run with environment settings
LTRACK_LOG_LEVEL=info LTRACK_LOG_FORMAT=json ./bin/ltrack
```

2. Configuration File (Default Priority):
```toml
# policy.toml
[log]
level = "info"      # Options: debug, info, warn, error
format = "json"     # Options: json, text
output_path = "/var/log/ltrack/app.log"
max_size = 100      # Maximum size in megabytes
max_age = 7         # Maximum age in days
max_backups = 5     # Maximum number of old log files
compress = true     # Compress old files
```

#### Log Levels Usage Guide:

- `debug`: Detailed information for debugging (Development)
  - Function entry/exit
  - Variable values
  - Detailed process information
  - Performance metrics

- `info`: General operational information (Production)
  - Service start/stop
  - Configuration loading
  - Monitor status changes
  - Normal operations

- `warn`: Warning messages for potential issues
  - Resource usage warnings
  - Recoverable errors
  - Performance degradation

- `error`: Error conditions requiring attention
  - Service failures
  - Critical errors
  - Unrecoverable situations

#### Environment Recommendations:

- Development: `debug` level for maximum visibility
- Testing: `debug` or `info` level based on testing needs
- Staging: `info` level to match production
- Production: `info` level for normal operations

### Configuration File Structure

```toml
# ltrack Monitor Policy (policy.toml)

# File Monitoring Configuration
[file_monitor]
enabled = true
directories = [
    "/path/to/monitor",
]

# Process Execution Monitoring Configuration
[exec_monitor]
enabled = true
watch_commands = [
    "bash",
    "python",
    "nginx"
]

# Network Monitoring Configuration
[network_monitor]
enabled = true
ports = [80, 443, 8080]
protocols = ["tcp", "udp"]

# Logging Configuration
[log]
level = "info"
format = "json"
output_path = "/var/log/ltrack/app.log"
max_size = 100    # MB
max_age = 7       # days
max_backups = 5   # files
compress = true
```

### Best Practices

1. Log Level Selection:
   - Use `info` in production for normal operations
   - Use `debug` only when detailed troubleshooting is needed
   - Set appropriate log rotation settings to manage disk usage

2. Configuration Management:
   - Keep production configuration in version control
   - Use environment-specific configuration files
   - Validate configuration changes before deployment

3. Monitoring Setup:
   - Enable only required monitors
   - Configure appropriate directories and commands
   - Regular review of monitored resources

### Running

```bash
sudo ltrack -config policy.toml
```


## Development

### Build Dependencies

```bash

# Build dependencies (Ubuntu)
sudo apt-get install -y clang llvm libelf-dev

# Common commands
make test       # Run unit tests
make generate   # Generate eBPF code
make package    # Create release package

```

### Performance Metrics

### Generate eBPF Code

```bash
make generate
```

### Contributing

Pull Requests and Issues are welcome! Please check our Contributing Guide for details.

### Performance Benchmarks

| Monitor Type | Event Latency | CPU Usage | Memory Usage |
|-------------|---------------|------------|--------------|
| File Monitor| < 1ms | < 1% | ~10MB |
| Process Monitor| < 0.5ms | < 0.5% | ~5MB |
| Network Monitor| < 1ms | < 1% | ~15MB |

### License
This project is licensed under the [MIT License](LICENSE).

### Contact

- Issues: GitHub Issues
- Email: support@mx-crafts.com
- Community: Discussions

### Acknowledgments

- eBPF
- Cilium
- Go


## Cite ltrack

If you use `ltrack` in your publication, please cite it by using the following BibTeX entry.

```bibtex
@Misc{ltrack,
  title =        {`ltrack`: security observability framework for ml/ai model file loading.},
  author =       {@bayuncao},
  howpublished = {\url{https://github.com/mxcrafts/ltrack}},
  year =         {2025}
}
```
