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
    <img src="../brand/logo-light.png" alt="ltrack - ML/AI 模型文件加载的安全可观测性框架" width=100px>
    <br />
    <p>ltrack - ML/AI 模型文件加载的安全可观测性框架</p>
  </div>
</h3>


<p align="center">
  <a href="../README.md"><img alt="README in English" src="https://img.shields.io/badge/English-d9d9d9"></a>
  <a href="README_CN.md"><img alt="简体中文版自述文件" src="https://img.shields.io/badge/简体中文-d9d9d9"></a>
</p>


## 概述

> [!NOTE]
> ltrack 是一个开源的安全可观测性工具，专门用于监控和分析机器学习（ML）和人工智能（AI）模型文件在加载和执行过程中的潜在风险。该工具使用 Golang 和 eBPF（扩展的伯克利包过滤器）构建，将低级内核跟踪的效率与现代系统编程的稳健性相结合，提供高性能、低开销的监控。通过关注关键系统行为和配置，ltrack 帮助开发人员、MLOps 工程师和安全研究人员识别 ML/AI 工作流中的漏洞、未授权访问和异常活动。

## 技术亮点

- 基于 eBPF 的高效性能
  利用 eBPF 执行轻量级的内核级事件跟踪，无需修改内核。这最大限度地减少了运行时开销（大多数情况下 CPU 使用率 <3%），同时实现了系统调用、网络流量和文件操作的实时观测。

- Golang 性能和可移植性
  利用 Golang 的并发模型和跨平台能力，确保高吞吐量的事件处理和在各种 Linux 发行版上的无缝部署。

- 零依赖监控
  避免依赖外部内核模块或代理，减少攻击面和操作复杂性。

## 功能特性

- 🔍 **文件监控**：监控指定目录中的文件操作（创建、删除、修改等）
- 🚀 **进程监控**：跟踪指定命令的执行
- 🌐 **网络监控**：监控特定端口和协议的网络活动
- 📝 **日志管理**：支持日志轮转、压缩和保留策略
- ⚡ **高性能**：基于 eBPF 技术的低开销系统监控
- 🔧 **可配置**：通过 TOML 文件灵活配置监控策略

## 为什么选择 ltrack？

- 低开销，高保真
  eBPF 的内核空间执行消除了昂贵的上下文切换，能够在不影响模型推理或训练性能的情况下精确跟踪系统事件。

- 实时告警
  集成日志系统（如 Elasticsearch、Prometheus）以主动响应威胁。

- 可扩展架构
  支持自定义检测器和集成的插件，Golang 的静态二进制打包简化了部署。

## 使用场景

- MLOps 流水线：通过审计模型部署过程增强 CI/CD 工作流程的安全性。
- 研究环境：保护实验模型和数据集免受意外访问或篡改。
- 合规性：通过强制执行严格的访问控制和审计跟踪满足监管要求（如 GDPR、HIPAA）。

## 快速开始

### 容器启动

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

### 构建本地镜像

```bash
cd deploy

# Using latest version
docker-compose up -d
```

### 通过编码编译

#### Prerequisites

- Linux kernel version >= 4.18
- Go version >= 1.21
- LLVM/Clang 11+

#### 安装并运行

```bash
# 通过源码编译
git clone https://github.com/mxcrafts/ltrack.git
cd ltrack
make && LTRACK_LOG_LEVEL=info LTRACK_LOG_FORMAT=json ./bin/ltrack ./bin/ltrack --config policy.toml
```


### 配置

#### 命令行选项

```bash
# 使用默认配置文件运行（policy.toml）
make && LTRACK_LOG_LEVEL=info LTRACK_LOG_FORMAT=json ./bin/ltrack ./bin/ltrack

# 使用指定的配置文件运行
make && LTRACK_LOG_LEVEL=info LTRACK_LOG_FORMAT=json ./bin/ltrack --config policy.toml
```

#### 日志级别配置

日志级别可以通过两种方式配置：

1. 环境变量（最高优先级）：
```bash
# 通过环境变量设置日志级别
export LTRACK_LOG_LEVEL=debug  # 选项：debug, info, warn, error
export LTRACK_LOG_FORMAT=json  # 选项：json, text

# 使用环境变量设置运行
LTRACK_LOG_LEVEL=info LTRACK_LOG_FORMAT=json ./bin/ltrack
```

2. 配置文件（默认优先级）：
```toml
# policy.toml
[log]
level = "info"      # 选项：debug, info, warn, error
format = "json"     # 选项：json, text
output_path = "/var/log/ltrack/app.log"
max_size = 100      # 最大大小（MB）
max_age = 7         # 最大保留天数
max_backups = 5     # 最大备份文件数
compress = true     # 压缩旧文件
```

#### 日志级别使用指南：

- `debug`：调试用详细信息（开发环境）
  - 函数进入/退出
  - 变量值
  - 详细的进程信息
  - 性能指标

- `info`：一般操作信息（生产环境）
  - 服务启动/停止
  - 配置加载
  - 监控状态变更
  - 正常操作

- `warn`：潜在问题的警告消息
  - 资源使用警告
  - 可恢复的错误
  - 性能下降

- `error`：需要注意的错误情况
  - 服务失败
  - 严重错误
  - 不可恢复的情况

#### 环境建议：

- 开发环境：使用 `debug` 级别以获得最大可见性
- 测试环境：根据测试需求使用 `debug` 或 `info` 级别
- 预发环境：使用 `info` 级别以匹配生产环境
- 生产环境：使用 `info` 级别进行正常操作

### 配置文件结构

```toml
# ltrack 监控策略 (policy.toml)

# 文件监控配置
[file_monitor]
enabled = true
directories = [
    "/path/to/monitor",
]

# 进程执行监控配置
[exec_monitor]
enabled = true
watch_commands = [
    "bash",
    "python",
    "nginx"
]

# 网络监控配置
[network_monitor]
enabled = true
ports = [80, 443, 8080]
protocols = ["tcp", "udp"]

# 日志配置
[log]
level = "info"
format = "json"
output_path = "/var/log/ltrack/app.log"
max_size = 100    # MB
max_age = 7       # 天
max_backups = 5   # 文件数
compress = true
```

### 最佳实践

1. 日志级别选择：
   - 生产环境使用 `info` 进行正常操作
   - 仅在需要详细故障排除时使用 `debug`
   - 设置适当的日志轮转设置以管理磁盘使用

2. 配置管理：
   - 在版本控制中保存生产配置
   - 使用环境特定的配置文件
   - 部署前验证配置更改

3. 监控设置：
   - 仅启用所需的监控器
   - 配置适当的目录和命令
   - 定期审查监控的资源

### 运行

```bash
sudo ltrack -config policy.toml
```

## 开发

### 构建依赖

```bash
# 构建依赖（Ubuntu）
sudo apt-get install -y clang llvm libelf-dev

# 常用命令
make test       # 运行单元测试
make generate   # 生成 eBPF 代码
make package    # 创建发布包
```

### 性能指标

| 监控类型 | 事件延迟 | CPU 使用率 | 内存使用 |
|----------|----------|------------|-----------|
| 文件监控 | < 1ms    | < 1%       | ~10MB     |
| 进程监控 | < 0.5ms  | < 0.5%     | ~5MB      |
| 网络监控 | < 1ms    | < 1%       | ~15MB     |

### 贡献

欢迎提交 Pull Requests 和 Issues！详情请查看我们的贡献指南。

### 许可证

本项目采用 [MIT 许可证](../LICENSE)。

### 联系方式

- 问题反馈：GitHub Issues
- 电子邮件：support@mx-crafts.com
- 社区：Discussions

### 致谢

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
