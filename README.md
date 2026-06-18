# ✦ Asterism

[![CI](https://github.com/sosopop/asterism/actions/workflows/ci.yml/badge.svg)](https://github.com/sosopop/asterism/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sosopop/asterism?label=release)](https://github.com/sosopop/asterism/tags)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/sosopop/asterism/actions/workflows/ci.yml)
[![Sanitizers](https://img.shields.io/badge/sanitizers-ASan%20%7C%20UBSan-success)](.github/workflows/ci.yml)
[![Language](https://img.shields.io/github/languages/top/sosopop/asterism)](https://github.com/sosopop/asterism)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

![Title Banner](assets/title_banner.png)

English | [中文](README_ZH.md)

Asterism is a lightweight reverse proxy for NAT traversal (intranet penetration). It exposes services behind NAT/firewalls to the public network through a relay with a public IP, enabling external clients to access TCP and HTTP services on private networks.

Typical use cases:

- Remotely access a home NAS or router admin panel
- Connect to office RDP, SSH, or other internal services
- Relay-to-agent message pushing (agent hosts a Web API for the relay/clients to call)
- **Portal mode** (port forwarding): Map a local port to a remote service via the relay-agent tunnel

## 🧩 Terminology & Component Roles

Asterism consists of four core concepts to keep the design clean:

- **Relay**: The central bridge with a public IP. It relays traffic between the Client and the Agent.
- **Agent**: The daemon running inside the private network. It connects to the Relay to establish the reverse tunnel.
- **Client**: The end-user or program (e.g. browser, curl) accessing target private resources via the Relay.
- **Portal**: A local port forwarding mode (SSH `-L` style). It listens on a local port and forwards traffic to the remote target via the Relay CONNECT tunnel.

## ❓ Why Asterism?

Asterism is designed for users who need a lightweight, self-hosted and easy-to-understand NAT traversal reverse proxy. It is not trying to become a full-featured networking platform. Instead, it focuses on a simple and practical goal: accessing private-network services through a public relay.

### Compared with ngrok

- **Fully self-hosted** — Asterism does not depend on a vendor-hosted cloud tunneling service. You run the relay on your own public server.
- **No cloud account dependency** — No third-party account, hosted tunnel address or external control plane is required.
- **Stable public entrypoint** — You control the public IP, listening ports, authentication and traffic path.
- **Better for private infrastructure** — Suitable for home labs, NAS access, office networks, customer-site maintenance and private service exposure.

### Compared with frp

- **Smaller scope, simpler mental model** — Asterism focuses on Relay, Agent, Client and Portal, making it easier to understand and operate.
- **Lightweight C/libuv implementation** — Built with C and libuv async I/O, designed to be small, fast and easy to embed.
- **Single-binary deployment** — No external runtime is required. Build once and run the generated binary.
- **Proxy-first design** — Supports HTTP Proxy and SOCKS5 Proxy as first-class access methods.
- **Portal mode for port forwarding** — Provides local port forwarding similar to `ssh -L`, useful for RDP, SSH, databases, web services and other TCP services.
- **Multi-agent routing by username** — Multiple agents can share the same relay, and clients can select the target private network by using different credentials.

### When to use Asterism

Asterism is a good fit when you want to:

- Access a home NAS, router admin panel or private web service remotely.
- Connect to office RDP, SSH, database or internal TCP services from outside the network.
- Use your own VPS or public server as a private NAT traversal relay.
- Avoid depending on a commercial tunneling provider.
- Use a lightweight alternative to large-featured tunneling systems when simple reverse proxy and port forwarding are enough.
- Study or customize a clear C/libuv implementation of NAT traversal, reverse proxy, SOCKS5 proxy and HTTP CONNECT tunneling.

In short, Asterism provides the self-hosted control of frp, the simple access style of ngrok, and a smaller C/libuv single-binary footprint.

---

## 🏗️ Architecture Overview

![Network Topology](assets/topology.png)

### 1. Standard Mode (Reverse HTTP/SOCKS5 Proxy)
Clients route proxy requests through the public Relay, which forwards traffic via the reverse tunnel to the intranet Agent.

```mermaid
graph LR
    Client["Client (Browser / Curl)"] -->|HTTP / SOCKS5 Proxy| Relay["Asterism Relay (Public IP)"]
    Agent["Asterism Agent (Intranet)"] -->|Reverse Tunnel| Relay
    Agent -->|Local Access| Target["Target Service (SSH / Web / NAS)"]

    style Client fill:#f9f,stroke:#333,stroke-width:2px,color:#000
    style Relay fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style Agent fill:#bfb,stroke:#333,stroke-width:2px,color:#000
```

### 2. Portal Mode (Local Port Forwarding)
Local applications connect to a local port listener (Portal), which automatically tunnels traffic to the remote target via the Relay.

```mermaid
graph LR
    App["Local Application"] -->|TCP Connection| Portal["Asterism Portal (Local Listener)"]
    Portal -->|HTTP CONNECT Tunnel| Relay["Asterism Relay (Public IP)"]
    Agent["Asterism Agent (Intranet)"] -->|Reverse Tunnel| Relay
    Agent -->|Local Access| Target["Target Service"]

    style Portal fill:#fcf,stroke:#333,stroke-width:2px,color:#000
    style Relay fill:#bbf,stroke:#333,stroke-width:2px,color:#000
    style Agent fill:#bfb,stroke:#333,stroke-width:2px,color:#000
```

**How it works (Standard Mode):**
1. **Agent** connects to the **Relay**'s agent connection port (`-o`) and establishes a persistent tunnel.
2. **Relay** listens for HTTP/SOCKS5 proxy requests on proxy ports (`-i`).
3. **Client** configures their proxy pointing to the **Relay** and authenticates using the **Agent**'s credentials.
4. **Relay** routes the request through the tunnel to the **Agent**, which forwards it to local resources and returns the response.

## ✨ Features

- **Cross-platform** — Windows, Linux, macOS, Android, iOS
- **High performance** — Event-driven architecture built on libuv async I/O
- **Protocol support** — HTTP proxy, SOCKS5 proxy (with optional UDP support)
- **Lightweight** — Pure C, no external runtime dependencies, single binary
- **Multi-user** — Multiple agents connect simultaneously, routed by username
- **Portal Support** — Easy port forwarding over the proxy tunnel

## 🛠️ Building

### Prerequisites

- CMake >= 3.16
- C compiler (GCC / Clang / MSVC)
- Node.js/npm for generating the vendored `llhttp` C parser sources during build
- Third-party libraries are referenced as Git submodules in `3rdparty/` (libuv, llhttp)

### Build Steps

```bash
# Clone the repository with submodules, or initialize them afterwards:
git submodule update --init --recursive

mkdir build
cd build
cmake ..
cmake --build . --config Release
```

The output is a single binary: `build/src/asterism/asterism` (or `asterism.exe` on Windows).

### Build with Unit Tests

```bash
# Ensure submodules are initialized:
git submodule update --init --recursive

mkdir build
cd build
cmake -DUNIT_TEST=ON ..
cmake --build . --config Debug
ctest --output-on-failure
```

## 🚀 Usage

### Command-Line Options

```
asterism [options]

Options:
  -h, --help                 Show help message
  -v, --verbose              Enable debug log output
  -V, --version              Display version number
  -i, --in-addr <address>    Relay proxy listen address (can be specified multiple times)
                             Example: -i http://0.0.0.0:8081
                             Example: -i socks5://0.0.0.0:8082
  -o, --out-addr <address>   Relay agent connection listen address
                             Example: -o tcp://0.0.0.0:1234
  -r, --remote-addr <address> Agent relay connection address
                             Example: -r tcp://1.2.3.4:1234
  -u, --user <username>      Agent authentication username
  -p, --pass <password>      Agent authentication password
  -d, --udp                  Enable SOCKS5 UDP support (disabled by default)
  -t, --udp-timeout <seconds> UDP session idle timeout (0 = no timeout)
  -T, --idle-timeout <seconds> TCP connection idle timeout in seconds (0 = disabled, default 300).
                             Idle but live tunnels (SSH/RDP/DB) stay up; dead peers are
                             detected via TCP keepalive.
  -A, --auth-sessions        Require HTTP basic authentication for the session list (/sessions)
      --public-sessions      Allow unauthenticated access to /sessions
  -U, --session-user <user>  Username for the session list authentication
  -P, --session-pass <pass>  Password for the session list authentication
```

### Security Notes

The relay-agent communication is transmitted as plaintext and provides no transport encryption. Use trusted networks, host-level encryption, or an external TLS/VPN layer when confidentiality is required.

### Quick Start

**Step 1: Start the Relay** (on a machine with a public IP)

```bash
asterism \
  -i http://0.0.0.0:8081 \
  -i socks5://0.0.0.0:8082 \
  -o tcp://0.0.0.0:1234 \
  -v
```

- `-i` sets proxy listen addresses; HTTP and SOCKS5 can run simultaneously.
- `-o` sets the port for agent connections.

**Step 2: Start the Agent** (on a machine behind NAT)

```bash
asterism \
  -r tcp://<relay_ip>:1234 \
  -u myuser \
  -p mypassword \
  -v
```

The agent automatically connects to the relay and maintains the tunnel, reconnecting every 10 seconds if disconnected.

**Step 3: Access LAN services through the proxy**

```bash
# Via HTTP proxy
curl "http://192.168.1.100:8080/api" \
  --proxy "http://<relay_ip>:8081" \
  --proxy-user "myuser:mypassword"

# Via SOCKS5 proxy
curl "http://192.168.1.100:8080/api" \
  --proxy "socks5://<relay_ip>:8082" \
  --proxy-user "myuser:mypassword"
```

---

### Portal Mode (Port Forwarding)

You can configure local port forwarding using the `-L` / `--portal` command-line option. This maps a local port to a remote destination via the relay's HTTP CONNECT tunnel:

```bash
asterism -L "local_addr:local_port#relay_addr#remote_addr:remote_port" -v
```

- **Format**: `local_address:local_port#relay_address#remote_address:remote_port`
- **Example**:
  ```bash
  asterism -L "127.0.0.1:6102#http://myuser:mypassword@127.0.0.1:8011#192.168.1.100:3389" -v
  ```
  This listens on local port `6102`. All incoming connections are forwarded to `192.168.1.100:3389` on the agent's network via the relay's HTTP CONNECT proxy at `127.0.0.1:8011` with credentials `myuser:mypassword`.

- **Multiple Portals**: You can specify `-L` multiple times to run multiple port forwarding rules concurrently:
  ```bash
  asterism \
    -L "127.0.0.1:3306#http://test:test@127.0.0.1:8011#192.168.1.100:3306" \
    -L "127.0.0.1:80#http://test:test@127.0.0.1:8011#192.168.1.100:80" \
    -v
  ```

---

### Multi-Agent Scenario

Multiple agents behind different NATs can connect to the same relay simultaneously, each identified by a unique username. Clients route to different agents by specifying different credentials, accessing each agent's local network resources.

```bash
# Agent A (home network)
asterism -r tcp://relay:1234 -u home -p pass_a -v

# Agent B (office network)
asterism -r tcp://relay:1234 -u office -p pass_b -v

# Access NAS on home network
curl http://192.168.1.10:5000 --proxy socks5://relay:8082 --proxy-user "home:pass_a"

# Access remote desktop on office network
curl http://10.0.0.50:3389 --proxy socks5://relay:8082 --proxy-user "office:pass_b"
```

### Querying Active Sessions

You can query the list of currently connected agent sessions by sending an HTTP GET request to `/sessions` on the relay's HTTP proxy address.

```bash
# Query active sessions
curl http://<relay_ip>:<http_port>/sessions
```

By default, this endpoint requires HTTP Basic Authentication. If `-U` / `--session-user` and `-P` / `--session-pass` are not configured, `/sessions` returns `401 Unauthorized`.

```bash
# Start relay with sessions list authentication
asterism -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 -U admin -P admin123

# Query with credentials
curl -u admin:admin123 http://<relay_ip>:8081/sessions
```

To intentionally restore the older public behavior, start the relay with `--public-sessions`:

```bash
asterism -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 --public-sessions
curl http://<relay_ip>:8081/sessions
```

`-A` / `--auth-sessions` is kept as a compatibility alias for the default authenticated policy.

## ⚙️ System Service Deployment

Asterism provides interactive management scripts to register agent, relay, or portal modes as background services/tasks across multiple operating systems. This allows running multiple instances on the same host under custom service names.

### Linux (systemd) & macOS (launchd)
A single unified script `service.sh` automatically detects your OS and configures systemd or launchd services.

* **Manage Service**: Run `sudo ./install/service.sh [install|uninstall]` or run without arguments for interactive prompts.
* **Linux Service Names**: Default is `asterism-relay` or `asterism-agent`. Shared binary is installed in `/opt/asterism/bin/`.
* **macOS Service Labels**: Default is `com.asterism.relay` or `com.asterism.agent`. Shared binary is installed in `/usr/local/bin/`.
* **Management Commands (Linux)**:
  ```bash
  sudo systemctl status asterism-relay      # Check status
  sudo systemctl restart asterism-relay     # Restart service
  sudo journalctl -u asterism-relay -f      # View real-time logs
  ```
* **Management Commands (macOS)**:
  ```bash
  sudo launchctl list com.asterism.relay                     # Check status
  sudo launchctl unload /Library/LaunchDaemons/com.asterism.relay.plist  # Stop service
  tail -f /usr/local/var/log/com.asterism.relay/asterism.log     # View logs
  ```

### Windows (Task Scheduler)
A single unified script `service.ps1` registers background tasks to run as `SYSTEM` at boot.

* **Manage Task**: Run `PowerShell` as Administrator, then run: `.\install\service.ps1 -Action [Install|Uninstall]`, or run without parameters for interactive prompts.
* **Task Names**: Default is `AsterismRelay` or `AsterismAgent`. Shared binary is installed in `C:\Program Files\Asterism\`.
* **Management Commands**:
  ```powershell
  schtasks /Query /TN AsterismRelay          # Check status
  schtasks /End /TN AsterismRelay            # Stop task
  schtasks /Run /TN AsterismRelay            # Start/Run task
  ```

## 📦 Embedding Asterism as a Library (SDK)

Asterism is built as a clean, modular library (`asterism_lib`) that you can easily integrate into your own C/C++ projects. All configurations are set via key-value options, and the engine runs asynchronously on top of libuv.

### SDK Header
To use the SDK, include `asterism.h` in your project:
```c
#include "asterism.h"
```

### SDK Code Example
Here is a complete, minimal example showing how to programmatically initialize and run an Asterism **Agent**:

```c
#include <stdio.h>
#include "asterism.h"

int main() {
    // 1. Create an Asterism instance
    asterism as = asterism_create();
    if (!as) {
        fprintf(stderr, "Failed to create Asterism instance\n");
        return 1;
    }

    // 2. Set options (e.g., configure as an Agent)
    asterism_set_option(as, ASTERISM_OPT_CONNECT_ADDR, "tcp://1.2.3.4:1234");
    asterism_set_option(as, ASTERISM_OPT_USERNAME, "my_agent");
    asterism_set_option(as, ASTERISM_OPT_PASSWORD, "my_password");

    // Optional: Enable verbose debugging output
    asterism_set_log_level(ASTERISM_LOG_DEBUG);

    printf("Starting Asterism Agent...\n");

    // 3. Run the event loop (this call blocks until the tunnel is stopped)
    int ret = asterism_run(as);
    if (ret != 0) {
        fprintf(stderr, "Asterism run error: %s\n", asterism_errno_description(ret));
    }

    // 4. Destroy the instance and clean up resources
    asterism_destroy(as);
    return ret;
}
```

To stop the running loop programmatically from another thread or signal handler, call:
```c
asterism_stop(as);
```

### CMake Integration
Link `asterism_lib` to your target in your `CMakeLists.txt`:
```cmake
add_executable(my_app main.c)
target_link_libraries(my_app PRIVATE asterism_lib)
```

## 📂 Project Structure

```
asterism/
├── 3rdparty/               # Third-party dependencies (integrated as Git submodules)
│   ├── libuv/              # Cross-platform async I/O library
│   └── llhttp/             # HTTP protocol parser
├── src/asterism/           # Core source code
│   ├── main.c              # Entry point and CLI argument parsing
│   ├── asterism.h/.c       # Public API interface
│   ├── asterism_core.h/.c  # Core: event loop, session management, protocol definitions
│   ├── asterism_stream.*   # TCP stream abstraction
│   ├── asterism_inner_*    # Proxy protocol implementations (HTTP / SOCKS5)
│   ├── asterism_outer_*    # Outer connection listener (agent connections)
│   ├── asterism_connector_*# Agent connector
│   ├── asterism_requestor_*# Request forwarding
│   ├── asterism_responser_*# Response forwarding
│   └── asterism_portal.*   # Portal mode forwarding
├── test/                   # Unit tests
├── install/                # Service installation scripts
├── CMakeLists.txt          # Build configuration
├── README.md               # English documentation
└── README_ZH.md            # Chinese documentation
```
