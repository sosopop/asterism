# ✦ Asterism

![Title Banner](assets/title_banner.png)

[English](README.md) | 中文

Asterism 是一个轻量级的内网穿透（NAT 穿透）反向代理工具。它通过一台具有公网 IP 的中继服务，将内网服务暴露到公网，使外部客户端能够访问 NAT/防火墙后面的 TCP 和 HTTP 服务。

典型应用场景：

- 远程访问家中的 NAS、路由器管理界面
- 连接公司内网的远程桌面（RDP）、SSH 等服务
- 中继向代理节点推送消息（代理节点建立 Web API 供中继或客户端调用）
- **Portal 模式**（端口转发）：通过中继与代理节点之间的隧道将本地端口映射到远端服务

## 🧩 术语解释与组件角色

为了清晰定义系统架构，Asterism 统一使用以下术语：

- **Relay (中继)**：运行在具有公网 IP 的服务器上，负责在中继端将客户端的请求与代理节点反向隧道进行桥接转发。
- **Agent (代理节点)**：运行在内网环境中的守护程序，主动连接 Relay 建立反向隧道，将流量最终导向内网的具体服务。
- **Client (客户端)**：最终发起代理请求的外部程序（如浏览器、curl 等），指定 Agent 的身份凭据接入 Relay 的代理端口。
- **Portal (传送门)**：本地端口转发模式（类似于 SSH `-L`）。在本地监听一个端口，并将所有连接请求通过中继的 CONNECT 隧道透明转发到远端服务。

## ❓ 为什么选择 Asterism？

Asterism 旨在为需要轻量级、自托管且易于理解的 NAT 穿透反向代理的用户提供服务。它并不试图成为一个功能繁多的网络平台，而是专注于一个简单而实用的目标：通过公网中继访问私有网络中的服务。

### 与 ngrok 对比

- **完全自托管** — Asterism 不依赖于运营商托管的云隧道服务。您可以在自己的公网服务器上运行中继（Relay）。
- **无云端账户依赖** — 无需第三方账号、托管隧道地址或外部控制面板。
- **稳定的公网入口** — 您可以完全控制公网 IP、监听端口、身份验证和流量路径。
- **更适合私有基础设施** — 非常适合个人实验室（Home Lab）、NAS 访问、办公室网络、客户现场维护和私有服务暴露。

### 与 frp 对比

- **范围更小，心智模型更简单** — Asterism 专注于 Relay（中继）、Agent（代理节点）、Client（客户端）和 Portal（传送门），更易于理解和操作。
- **轻量级 C/libuv 实现** — 基于 C 语言和 libuv 异步 I/O 构建，设计小巧、高效且易于嵌入。
- **单二进制部署** — 无需外部运行环境。只需编译一次，即可运行生成的单一可执行文件。
- **代理优先设计** — 将 HTTP 代理和 SOCKS5 代理作为一等公民（First-class）支持。
- **Portal 模式支持端口转发** — 提供类似于 `ssh -L` 的本地端口转发功能，适用于 RDP、SSH、数据库、Web 服务和其他 TCP 服务。
- **多 Agent 账号路由** — 多个 Agent 节点可以共享同一个中继，Client 端可以通过使用不同的账号凭据来选择连接到目标私有网络。

### 什么时候使用 Asterism

在以下场景中，Asterism 是一个理想的选择：

- 远程访问家中的 NAS、路由器管理面板或私有 Web 服务。
- 从外部网络连接到办公室的 RDP、SSH、数据库或内部 TCP 服务。
- 将您自己的 VPS 或公网服务器用作私有 NAT 穿透中继。
- 避免对商业隧道服务商的依赖。
- 在简单的反向代理和端口转发即可满足需求时，作为大而全的隧道系统的轻量级替代方案。
- 学习或定制 NAT 穿透、反向代理、SOCKS5 代理和 HTTP CONNECT 隧道等技术的 C/libuv 清晰实现。

简而言之，Asterism 结合了 frp 的自托管控制力、ngrok 的简单接入风格以及 C/libuv 单二进制的轻量占用。

---

## 🏗️ 架构概览

![网络拓扑结构](assets/topology.png)

### 1. 标准代理模式 (反向 HTTP/SOCKS5 代理)
外部客户端通过访问公网 Relay 的代理监听端口，将请求通过反向隧道路由到内网 Agent 节点，从而访问内网资源。

```mermaid
graph LR
    Client["客户端 (Client) (浏览器 / Curl)"] -->|HTTP / SOCKS5 代理| Relay["Asterism 中继 (Relay) (公网 IP)"]
    Agent["Asterism 代理 (Agent) (内网环境)"] -->|反向隧道| Relay
    Agent -->|本地访问| Target["目标服务 (SSH / Web / NAS)"]

    style Client fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style Relay fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style Agent fill:#bfb,stroke:#333,stroke-width:2px,color:#000
```

### 2. Portal 模式 (本地端口转发)
本地应用连接本地 Portal 端口监听，Portal 自动通过中继代理隧道将流量透明映射至远端的目标服务器。

```mermaid
graph LR
    App["本地应用"] -->|TCP 连接| Portal["Asterism 传送门 (Portal) (本地监听)"]
    Portal -->|HTTP CONNECT 隧道| Relay["Asterism 中继 (Relay) (公网 IP)"]
    Agent["Asterism 代理 (Agent) (内网环境)"] -->|反向隧道| Relay
    Agent -->|本地访问| Target["目标服务"]

    style Portal fill:#fcf,stroke:#333,stroke-width:2px,color:#000
    style Relay fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style Agent fill:#bfb,stroke:#333,stroke-width:2px,color:#000
```

**工作流程 (标准代理模式):**
1. **Agent** 启动后，主动连接 **Relay** 的代理节点监听端口 (`-o`) 建立持久隧道。
2. **Relay** 在代理端口 (`-i`) 监听代理请求（HTTP/SOCKS5）。
3. **Client** 配置代理地址指向 **Relay**，并携带 **Agent** 的认证账户进行请求。
4. **Relay** 接收请求，通过隧道将其路由给对应 **Agent**，由 Agent 请求本地资源并原路返回响应。

## 🛠️ 编译

### 编译依赖

- CMake >= 2.8
- C 编译器（GCC / Clang / MSVC）
- 第三方库作为 Git 子模块 (Submodule) 引用在 `3rdparty/` 目录中 (libuv、http-parser)

### 构建步骤

```bash
# 克隆仓库后，需要初始化并更新子模块：
git submodule update --init --recursive

mkdir build
cd build
cmake ..
cmake --build . --config Release
```

构建产物为单一可执行文件：`build/src/asterism/asterism`（Windows 下为 `asterism.exe`）。

### 构建单元测试

```bash
# 确保子模块已初始化：
git submodule update --init --recursive

mkdir build
cd build
cmake -DUNIT_TEST=ON ..
cmake --build . --config Debug
```

## 🚀 使用方法

### 命令行参数

```
asterism [options]

选项:
  -h, --help                 显示帮助信息
  -v, --verbose              开启调试日志输出
  -V, --version              显示版本号
  -i, --in-addr <address>    Relay 代理监听地址（可多次指定）
                             示例: -i http://0.0.0.0:8081
                             示例: -i socks5://0.0.0.0:8082
  -o, --out-addr <address>   Relay 代理节点连接监听地址
                             示例: -o tcp://0.0.0.0:1234
  -r, --remote-addr <address> Agent 中继连接地址
                             示例: -r tcp://1.2.3.4:1234
  -u, --user <username>      Agent 认证用户名
  -p, --pass <password>      Agent 认证密码
  -d, --udp                  启用 SOCKS5 UDP 支持（默认关闭）
  -t, --udp-timeout <seconds> UDP 会话空闲超时（0 表示不超时）
  -A, --auth-sessions        启用会话列表接口（/sessions）的 HTTP Basic 认证
  -U, --session-user <user>  会话列表认证用户名
  -P, --session-pass <pass>  会话列表认证密码
```

### 快速开始

**第一步：启动中继（Relay）**（在有公网 IP 的机器上）

```bash
asterism \
  -i http://0.0.0.0:8081 \
  -i socks5://0.0.0.0:8082 \
  -o tcp://0.0.0.0:1234 \
  -v
```

- `-i` 指定代理监听地址，支持同时开启 HTTP 和 SOCKS5 代理。
- `-o` 指定 Agent 接入端口。

**第二步：启动代理节点（Agent）**（在内网机器上）

```bash
asterism \
  -r tcp://<relay_ip>:1234 \
  -u myuser \
  -p mypassword \
  -v
```

Agent 会自动连接 Relay 并保持隧道，断线后每 10 秒自动重连。

**第三步：通过代理访问内网服务**

```bash
# 通过 HTTP 代理
curl "http://192.168.1.100:8080/api" \
  --proxy "http://<relay_ip>:8081" \
  --proxy-user "myuser:mypassword"

# 通过 SOCKS5 代理
curl "http://192.168.1.100:8080/api" \
  --proxy "socks5://<relay_ip>:8082" \
  --proxy-user "myuser:mypassword"
```

---

### Portal 模式 (端口转发)

你可以使用 `-L` / `--portal` 命令行选项来配置本地端口转发。这能把本地的一个端口通过 Relay 的 HTTP CONNECT 隧道转发到指定目标：

```bash
asterism -L "local_addr:local_port#relay_addr#remote_addr:remote_port" -v
```

- **格式**：`本地地址:本地端口#中继地址#远端地址:远端端口`
- **示例**：
  ```bash
  asterism -L "127.0.0.1:6102#http://myuser:mypassword@127.0.0.1:8011#192.168.1.100:3389" -v
  ```
  这将在本地监听 `6102` 端口，并将所有连接请求通过隧道映射到 Agent 所在内网中的 `192.168.1.100:3389`。中继服务器地址为 `127.0.0.1:8011`，认证信息为 `myuser:mypassword`。

- **多端口转发**：你可以指定多次 `-L` 参数以同时运行多条端口转发规则：
  ```bash
  asterism \
    -L "127.0.0.1:3306#http://test:test@127.0.0.1:8011#192.168.1.100:3306" \
    -L "127.0.0.1:80#http://test:test@127.0.0.1:8011#192.168.1.100:80" \
    -v
  ```

---

### 多代理节点场景

多个内网 Agent 可以同时接入同一台 Relay，使用不同的用户名进行区分。外部客户端通过指定不同的 Agent 凭据，即可路由访问各自内网中的资源。

```bash
# 代理节点 A（家庭网络）
asterism -r tcp://relay:1234 -u home -p pass_a -v

# 代理节点 B（公司网络）
asterism -r tcp://relay:1234 -u office -p pass_b -v

# 访问家庭网络中的 NAS
curl http://192.168.1.10:5000 --proxy socks5://relay:8082 --proxy-user "home:pass_a"

# 访问公司网络中的远程桌面
curl http://10.0.0.50:3389 --proxy socks5://relay:8082 --proxy-user "office:pass_b"
```

### 查询在线 Agent 会话列表

您可以通过向 Relay 的 HTTP 代理地址发送 HTTP GET 请求访问 `/sessions`，来查询当前已连接的 Agent 会话列表：

```bash
# 查询在线 Agent 列表
curl http://<relay_ip>:<http_port>/sessions
```

默认情况下该接口是公开的。您可以通过 `-A` / `--auth-sessions` 选项开启 HTTP Basic 认证，并结合 `-U` / `--session-user` 和 `-P` / `--session-pass` 设置查询接口的用户名与密码：

```bash
# 启动 Relay 并开启会话列表验证
asterism -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 -A -U admin -P admin123

# 携带账密查询
curl -u admin:admin123 http://<relay_ip>:8081/sessions
```

## ⚙️ 系统服务部署

Asterism 提供了交互式管理脚本，在不同的操作系统中将中继（Relay）、代理（Agent）或传送门（Portal）模式注册为系统后台服务/任务，以支持开机自启。脚本支持在同一台机器上以不同的服务名称部署多个实例。

### Linux (systemd) 与 macOS (launchd)
使用统一的 `service.sh` 脚本，自动识别操作系统并配置 systemd 或 launchd 服务。

* **管理服务**：运行 `sudo ./install/service.sh [install|uninstall]`，或在不加参数的情况下直接运行以进入交互式菜单。
* **Linux 服务名称**：默认为 `asterism-relay` 或 `asterism-agent`。共享可执行文件安装在 `/opt/asterism/bin/`。
* **macOS 服务标签**：默认为 `com.asterism.relay` 或 `com.asterism.agent`。共享可执行文件安装在 `/usr/local/bin/`。
* **常用管理命令 (Linux)**：
  ```bash
  sudo systemctl status asterism-relay      # 查看状态
  sudo systemctl restart asterism-relay     # 重启服务
  sudo journalctl -u asterism-relay -f      # 实时查看日志
  ```
* **常用管理命令 (macOS)**：
  ```bash
  sudo launchctl list com.asterism.relay                     # 查看状态
  sudo launchctl unload /Library/LaunchDaemons/com.asterism.relay.plist  # 停止服务
  tail -f /usr/local/var/log/com.asterism.relay/asterism.log     # 查看日志
  ```

### Windows (任务计划程序)
使用统一的 `service.ps1` 脚本，将服务注册为以 `SYSTEM` 权限运行的系统启动任务。

* **管理任务**：以管理员权限运行 `PowerShell`，然后执行：`.\install\service.ps1 -Action [Install|Uninstall]`，或在不加参数的情况下运行以进入交互式菜单。
* **任务名称**：默认为 `AsterismRelay` 或 `AsterismAgent`。共享可执行文件安装在 `C:\Program Files\Asterism\`。
* **常用管理命令**：
  ```powershell
  schtasks /Query /TN AsterismRelay          # 查看状态
  schtasks /End /TN AsterismRelay            # 停止任务
  schtasks /Run /TN AsterismRelay            # 启动/运行任务
  ```

## 📦 将 Asterism 作为库嵌入使用 (SDK)

Asterism 被设计为一个轻量级、模块化的静态库（`asterism_lib`），您可以非常方便地将其集成到自己的 C/C++ 项目中。所有的配置均通过键值对（options）来进行设置，核心引擎基于 libuv 异步事件循环运行。

### SDK 头文件
要在项目中使用 SDK，请引入 `asterism.h`：
```c
#include "asterism.h"
```

### SDK 调用示例
以下是一个精简的调用示例，展示了如何在代码中初始化并启动一个 Asterism **Agent（代理端）**：

```c
#include <stdio.h>
#include "asterism.h"

int main() {
    // 1. 创建 Asterism 实例
    asterism as = asterism_create();
    if (!as) {
        fprintf(stderr, "创建 Asterism 实例失败\n");
        return 1;
    }

    // 2. 设置配置选项（例如，配置为 Agent 模式）
    asterism_set_option(as, ASTERISM_OPT_CONNECT_ADDR, "tcp://1.2.3.4:1234");
    asterism_set_option(as, ASTERISM_OPT_USERNAME, "my_agent");
    asterism_set_option(as, ASTERISM_OPT_PASSWORD, "my_password");

    // 可选：启用调试级别日志输出
    asterism_set_log_level(ASTERISM_LOG_DEBUG);

    printf("正在启动 Asterism Agent...\n");

    // 3. 运行事件循环（此调用会阻塞，直到隧道停止）
    int ret = asterism_run(as);
    if (ret != 0) {
        fprintf(stderr, "Asterism 运行错误: %s\n", asterism_errno_description(ret));
    }

    // 4. 销毁实例并释放资源
    asterism_destroy(as);
    return ret;
}
```

如果需要在其他线程或信号处理函数中编程式地停止运行的事件循环，只需调用：
```c
asterism_stop(as);
```

### CMake 集成
在您的 `CMakeLists.txt` 中将 `asterism_lib` 链接到您的目标：
```cmake
add_executable(my_app main.c)
target_link_libraries(my_app PRIVATE asterism_lib)
```

## 📂 项目结构

```
asterism/
├── 3rdparty/               # 第三方依赖
│   ├── libuv/              # 跨平台异步 I/O 库
│   └── http-parser/        # HTTP 协议解析器
├── src/asterism/           # 核心源码
│   ├── main.c              # 程序入口与命令行解析
│   ├── asterism.h/.c       # 公共 API 接口
│   ├── asterism_core.h/.c  # 核心：事件循环、会话管理、协议定义
│   ├── asterism_stream.*   # TCP 流抽象
│   ├── asterism_inner_*    # 代理协议实现（HTTP / SOCKS5）
│   ├── asterism_outer_*    # 外部连接监听（Agent 接入）
│   ├── asterism_connector_*# Agent 连接器
│   ├── asterism_requestor_*# 请求转发
│   ├── asterism_responser_*# 响应转发
│   └── test/               # 单元测试
├── install/                # 服务安装与卸载脚本
├── CMakeLists.txt          # 构建配置
├── README.md               # 英文文档
└── README_ZH.md            # 中文文档
```

## 📬 联系方式

- Email: 12178761@qq.com
- QQ: 12178761
- 微信: mengchao1102

如果本项目对您有帮助，欢迎 Star 支持！
