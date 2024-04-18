
# Tune.sh
## 功能概述

- **自动更新**: 自动安装系统和软件的更新。
- **带宽限制**: 设置网络接口的月带宽使用上限。
- **CPU滥用自动关机**: 当CPU使用率超过设定阈值时自动关闭服务器。
- **DDoS自动关机**: 当检测到DDoS攻击时自动关闭服务器。
- **SSH安全设置**: 提高SSH登录的安全性。
- **系统调优**: 调整系统设置以优化性能。
- **BBRx和BBRv3安装**：安装BBRx或BBRv3来优化网络性能。

## 使用方法

使用此脚本前，请确保您具有root权限。脚本的使用方式如下：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/jerry048/Tune/main/tune.sh) [选项]
```

### 选项说明

- `-a`: 启动自动更新。
- `-b`: 设置带宽限制。
- `-c`: 设置CPU滥用自动关机。
- `-d`: 启动DDoS自动关机。
- `-s`: 进行SSH安全设置。
- `-t`: 执行系统调优。
- `-x`: 安装BBRx。
- `-3`: 安装BBRv3。
- `-h`: 显示帮助信息。

### 示例

启动自动更新和设置带宽限制：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/jerry048/Tune/main/tune.sh) -a -b
```
## 功能介绍：

### 1. 带宽限制 (Bandwidth Limit)
这个功能旨在限制服务器的网络接口在一个设定的时间周期（通常是一个月）内使用的总带宽量。它通过监控网络接口的数据流量来实现，一旦达到设定的阈值，就会触发关机，避免产生预期外的费用。

**实现方法**：
- 用户需要指定月带宽上限（GB）和带宽刷新日。刷新日是指每个月带宽计量重置的日期。
- 当达到设定的带宽阈值时，脚本将会触发关机。

### 2. 带宽限制 (CPU Abuse Shutdown)
此功能用于在CPU使用率超过设定的阈值时自动关闭服务器，以防止因过度使用CPU而导致的资源滥用。
#### 实现方法

-   用户需要设置一个CPU使用率的上限值（百分比）。当系统监测到CPU使用率持续超过此阈值时，会触发自动关机操作。
-   脚本通过周期性检查系统的CPU使用率来实现此功能。如果CPU使用率连续30分钟超过设定阈值，脚本将执行关机命令。

### 3. DDoS自动关机 (DDoS Auto Shutdown)
这个功能用于增加服务器在遭受DDoS（分布式拒绝服务）攻击时的安全性。通过监控网络流量异常增长来检测潜在的DDoS攻击，一旦检测到攻击，自动关闭服务器以保护系统和数据。

**实现方法**：
- 设置阈值，包括Mbps（兆比特每秒）和pps（每秒数据包数量），以确定何时认为是DDoS攻击。
- 如果在设定时间内（例如10分钟）持续超过阈值，则自动执行关机操作。

### 4. SSH安全设置 (SSH Security Settings)
此功能提高SSH服务的安全性，包括更改默认端口、禁用密码认证和启用基于密钥的认证。

**实现方法**：
- 用户可以更改SSH服务的端口号，这有助于避免自动化的网络扫描工具发现。
- 禁用密码认证并启用基于密钥的认证，这种方式比传统密码认证更为安全，因为它依赖于密钥对而非可破解的密码。
- 还包括配置Fail2ban工具，它能够监控登录尝试，并在检测到恶意尝试时自动封禁IP地址。

### 4. 系统调优 (System Tuning)
这个功能通过调整各种系统和网络参数来优化服务器的性能。

**实现方法**：
- **内核参数调整**：例如，增加TCP缓冲区大小、修改系统队列长度等，这些改变有助于提高网络吞吐量和减少延迟。
- **性能优化**：安装和配置`Tuned`和其他系统性能优化工具来自动调整和优化服务器的运行状态。
- **资源限制**：例如，设置文件打开数量的限制，这可以防止某些类型的资源耗尽攻击。

通过这些功能，你的服务器不仅能够更有效地管理资源，还能提高对外部威胁的防护能力，保障系统稳定运行。

## 注意

- 在使用脚本前请确保您具有root用户权限。
- 在执行SSH安全设置时，请仔细跟随指示操作，以避免不必要的服务中断。
- 使用DDoS自动关机功能时，需要确保已正确配置阈值以避免误操作。
- 部分功能如BBRx和BBRv3安装可能需要重启系统以生效。
- 系统参数调整可能需要根据具体的系统配置和需求进行微调。

最后，请在使用此脚本前备份重要数据，以防万一出现不可预见的问题。
