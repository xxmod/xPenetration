# xPenetration

> Go 编写的内网穿透/端口转发工具：服务端统一分配隧道，客户端按配置连接并转发；支持密钥鉴权与 Web 管理界面。

---

## 特性

- 密钥验证（支持全局密钥与客户端独立密钥）
- TCP/UDP 隧道（在服务端映射端口，对外提供访问）
- 局域网设备穿透（可穿透同一局域网内其他设备的端口，不仅限于本机）
- 支持使用TCP封装UDP传输UDP数据包（作为备用选项，可能导致丢包）
- Web 管理界面（查看/调整服务端配置，支持 Basic Auth 认证保护）
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

Web 管理界面默认地址：`http://0.0.0.0:7500`（以配置为准）。

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

服务端配置示例见 `configs/server.example.yaml`：

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

客户端配置示例见 `configs/client.example.yaml`：

- `client.server_addr` / `client.server_port`
- `client.client_name`：必须与服务端 `clients[].name` 匹配
- `client.secret_key`：需与服务端全局密钥或该客户端独立密钥一致

## 使用场景示例

### 场景1：穿透本机端口

在客户端所在机器上运行SSH服务（22端口），将其映射到服务端的10022端口：

```yaml
tunnels:
  - name: "ssh"
    client_port: 22
    server_port: 10022
    protocol: "tcp"
    # target_ip 默认为 127.0.0.1，可省略
```

访问方式：`ssh user@your-server.com -p 10022`

### 场景2：穿透同一局域网下其他设备

客户端在家庭局域网中，想要穿透局域网内的NAS设备（IP: 192.168.1.100）的SSH服务：

```yaml
tunnels:
  - name: "nas-ssh"
    client_port: 22
    server_port: 20022
    protocol: "tcp"
    target_ip: "192.168.1.100"  # NAS设备的局域网IP
```

访问方式：`ssh user@your-server.com -p 20022`

### 场景3：穿透路由器管理界面

穿透路由器（IP: 192.168.1.1）的Web管理界面：

```yaml
tunnels:
  - name: "router-web"
    client_port: 80
    server_port: 20080
    protocol: "tcp"
    target_ip: "192.168.1.1"
```

访问方式：在浏览器访问 `http://your-server.com:20080`

### 场景4：穿透摄像头UDP流

穿透局域网内摄像头（IP: 192.168.1.50）的RTSP/UDP流：

```yaml
tunnels:
  - name: "camera-udp"
    client_port: 8554
    server_port: 18554
    protocol: "udp"
    udp_mode: "native"
    target_ip: "192.168.1.50"
```
