# xPenetration

> Go 编写的内网穿透/端口转发工具：服务端统一分配隧道，客户端按配置连接并转发；支持密钥鉴权与 Web 管理界面。

---

## 特性

- 密钥验证（支持全局密钥与客户端独立密钥）
- TCP/UDP 隧道（在服务端映射端口，对外提供访问）
- Web 管理界面（查看/调整服务端配置）
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

```bash
# 使用示例配置启动
bin/xpen-server -c configs/server.yaml
```

Web 管理界面默认地址：`http://0.0.0.0:7500`（以配置为准）。

说明：如果未找到配置文件，服务端会以默认端口启动 Web 界面用于配置。

### 3) 启动客户端

> 于无公网ip的客户端启动

```bash
# 使用示例配置启动
bin/xpen-client -c configs/client.yaml
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
- `clients[]`：按客户端名称分配隧道（可为单个客户端设置独立 `secret_key`）
- `clients[].tunnels[]`：
  - `client_port`：客户端本地服务端口
  - `server_port`：服务端对外暴露端口
  - `protocol`：`tcp` 或 `udp`

客户端配置示例见 `configs/client.example.yaml`：

- `client.server_addr` / `client.server_port`
- `client.client_name`：必须与服务端 `clients[].name` 匹配
- `client.secret_key`：需与服务端全局密钥或该客户端独立密钥一致

## License

本项目基于MIT许可证
