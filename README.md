# xPenetration

> Go 编写的内网穿透/端口转发工具：服务端统一分配隧道，客户端按配置连接并转发；支持密钥鉴权与 Web 管理界面。

---

## 特性

- 密钥验证（支持全局密钥与客户端独立密钥）
- TCP/UDP 隧道（在服务端映射端口，对外提供访问）
- TCP 隧道 TLS 加密（可选，使用证书对外提供 HTTPS 等加密连接）
- **ACME 自动证书**（支持 Let's Encrypt、ZeroSSL 等，自动申请与续签 SSL 证书）
  - HTTP-01 挑战（需开放 80 端口）
  - DNS-01 挑战（支持 Cloudflare、阿里云 DNS、腾讯云 DNSPod，无需开放 80 端口，支持通配符证书）
  - EAB 支持（用于 ZeroSSL、Google Trust Services 等需要外部账户绑定的 CA）
- 局域网设备穿透（可穿透同一局域网内其他设备的端口，不仅限于本机）
- 隧道配置由服务端统一指定，客户端仅作为节点连接
- 支持使用TCP封装UDP传输UDP数据包（作为备用选项）
- Web 管理界面（查看/调整服务端配置，支持 Basic Auth 认证保护、HTTPS）
- 可通过网页状态码判断服务健康状态
- 客户端自动重连

## 快速开始

### 1）下载或构建

#### 1.1）于[release](https://github.com/xxmod/xPenetration/releases)中下载合适的版本

#### 1.2）构建

```bash
# Linux/macOS
./build.sh

# 或使用 Makefile
make build
```

Windows：运行 `build.bat`，产物在 `bin/`。

### 2) 启动服务端

> 于有公网IP的服务器启动

实例配置文件是[server.example.yaml](https://github.com/xxmod/xPenetration/blob/main/configs/server.example.yaml)，复制到本地后修改为 `client.yaml` 放于根目录下

```bash
# 使用示例配置启动
bin/xpen-server -c server.yaml
```

Web 管理界面默认地址：`http://0.0.0.0:7500`可以公网ip连接管理。

说明：如果未找到配置文件，服务端会以默认端口启动 Web 界面用于配置，此时会根据web生成配置文件。

### 3) 启动客户端

> 于无公网ip的客户端启动

配置文件在[client.example.yaml](https://github.com/xxmod/xPenetration/blob/main/configs/client.example.yaml)找到，复制到本地后修改为 `client.yaml` 放于根目录下会自动识别

```bash
# 使用示例配置启动
bin/xpen-client -c client.yaml
```

也可以只用命令行参数：

```bash
bin/xpen-client -s <server_addr> -p 7000 -k <secret_key> -n <client_name>
```

## 配置要点

### 服务状态监控

访问 `/status/` 路径可查看服务运行状态，自动检测最近20分钟内的错误日志：

- 如果存在 ERROR 日志或有已配置但未连接的主机：返回状态码 **220**，显示 `Some Services Wrong`
- 如果没有错误：返回状态码 **200**，显示 `All Services OK`

示例：`http://your-server.com:7500/status/`端口取决于你的管理端口

### 配置文件内容

服务端配置示例见 `configs/server.example.yaml`（配置均可在面板中调节）：

- `server.listen_addr` / `server.control_port`：客户端连接的控制通道监听地址与端口
- `server.web_port`：Web 管理界面端口
- `server.secret_key`：全局密钥
- `server.web_auth`：（可选）Web 管理界面 Basic Auth 认证，配置 `username` 和 `password` 后访问管理界面需要登录
- `clients[]`：按客户端名称分配隧道（可为单个客户端设置独立 `secret_key`）
- `clients[].tunnels[]`：
  - `client_port`：客户端本地服务端口
  - `server_port`：服务端对外暴露端口
  - `protocol`：`tcp` 或 `udp`
  - `target_ip`：（可选）目标设备IP地址，默认为 `127.0.0.1`（本机）。可设置为局域网内其他设备的IP地址（如 `192.168.1.100`），实现穿透同一局域网下其他设备的端口
  - `enable_tls`：（可选）是否启用 TLS 加密，仅对 TCP 隧道有效。启用后服务端对外提供 TLS 加密连接（如 HTTPS），需先配置 `server.web_tls` 证书

客户端配置示例见 `configs/client.example.yaml`：

- `client.server_addr` / `client.server_port`
- `client.client_name`：必须与服务端 `clients[].name` 匹配
- `client.secret_key`：需与服务端全局密钥或该客户端独立密钥一致

### ACME 自动证书配置

xPenetration 支持通过 ACME 协议自动申请和续签 SSL 证书（如 Let's Encrypt），可用于 Web 管理界面 HTTPS 和 TLS 隧道。

配置位于 `server.yaml` 的 `acme` 部分，也可通过 Web 管理界面的「SSL配置」页面进行配置：

```yaml
acme:
  enabled: true                # 启用 ACME
  email: "admin@example.com"   # 注册邮箱
  domains:                     # 证书域名
    - "example.com"
  accept_tos: true             # 同意服务条款
  auto_renew: true             # 自动续签
  
  # 验证方式（二选一）
  challenge_type: "http-01"    # HTTP-01 需开放 80 端口
  # challenge_type: "dns-01"   # DNS-01 无需 80 端口，支持通配符
  
  # DNS-01 配置（仅 dns-01 模式需要）
  dns_provider: "cloudflare"   # cloudflare / alidns / tencentcloud
  dns_config: '{"api_token": "your-cloudflare-api-token"}'
```

#### 支持的 DNS 提供商

| 提供商        | dns_provider     | dns_config 格式                                          |
| ------------- | ---------------- | -------------------------------------------------------- |
| Cloudflare    | `cloudflare`   | `{"api_token": "xxx"}`                                 |
| 阿里云 DNS    | `alidns`       | `{"access_key_id": "xxx", "access_key_secret": "xxx"}` |
| 腾讯云 DNSPod | `tencentcloud` | `{"secret_id": "xxx", "secret_key": "xxx"}`            |

#### EAB 配置（ZeroSSL 等）

部分 CA（如 ZeroSSL、Google Trust Services）需要 External Account Binding：

```yaml
acme:
  enabled: true
  ca_server: "https://acme.zerossl.com/v2/DV90"
  eab_enabled: true
  eab_kid: "your-eab-kid"
  eab_hmac_key: "your-eab-hmac-key"
```

## 许可证

MIT License
