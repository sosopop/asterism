# ✦ Asterism

English | [中文](README_ZH.md)

Asterism is a lightweight reverse proxy for NAT traversal (intranet penetration). It exposes services behind NAT/firewalls to the public network through a relay with a public IP, enabling external clients to access TCP and HTTP services on private networks.

Typical use cases:

- Remotely access a home NAS or router admin panel
- Connect to office RDP, SSH, or other internal services
- Relay-to-agent message pushing (agent hosts a Web API for the relay/clients to call)
- **Portal mode** (port forwarding): Map a local port to a remote service via the relay-agent tunnel

## Terminology & Component Roles

Asterism consists of four core concepts to keep the design clean:

- **Relay**: The central bridge with a public IP. It relays traffic between the Client and the Agent.
- **Agent**: The daemon running inside the private network. It connects to the Relay to establish the reverse tunnel.
- **Client**: The end-user or program (e.g. browser, curl) accessing target private resources via the Relay.
- **Portal**: A local port forwarding mode (SSH `-L` style). It listens on a local port and forwards traffic to the remote target via the Relay CONNECT tunnel.

---

## Architecture Overview

### 1. Standard Mode (Reverse HTTP/SOCKS5 Proxy)
Clients route proxy requests through the public Relay, which forwards traffic via the reverse tunnel to the intranet Agent.

```mermaid
graph LR
    Client["Client (Browser / Curl)"] -->|HTTP / SOCKS5 Proxy| Relay["Asterism Relay (Public IP)"]
    Agent["Asterism Agent (Intranet)"] -->|Reverse Tunnel| Relay
    Agent -->|Local Access| Target["Target Service (SSH / Web / NAS)"]

    style Client fill:#f9f,stroke:#333,stroke-width:2px
    style Relay fill:#bbf,stroke:#333,stroke-width:2px
    style Agent fill:#bfb,stroke:#333,stroke-width:2px
```

### 2. Portal Mode (Local Port Forwarding)
Local applications connect to a local port listener (Portal), which automatically tunnels traffic to the remote target via the Relay.

```mermaid
graph LR
    App["Local Application"] -->|TCP Connection| Portal["Asterism Portal (Local Listener)"]
    Portal -->|HTTP CONNECT Tunnel| Relay["Asterism Relay (Public IP)"]
    Agent["Asterism Agent (Intranet)"] -->|Reverse Tunnel| Relay
    Agent -->|Local Access| Target["Target Service"]

    style Portal fill:#fcf,stroke:#333,stroke-width:2px
    style Relay fill:#bbf,stroke:#333,stroke-width:2px
    style Agent fill:#bfb,stroke:#333,stroke-width:2px
```

**How it works (Standard Mode):**
1. **Agent** connects to the **Relay**'s agent connection port (`-o`) and establishes a persistent tunnel.
2. **Relay** listens for HTTP/SOCKS5 proxy requests on proxy ports (`-i`).
3. **Client** configures their proxy pointing to the **Relay** and authenticates using the **Agent**'s credentials.
4. **Relay** routes the request through the tunnel to the **Agent**, which forwards it to local resources and returns the response.

## Features

- **Cross-platform** — Windows, Linux, macOS, Android, iOS
- **High performance** — Event-driven architecture built on libuv async I/O
- **Protocol support** — HTTP proxy, SOCKS5 proxy (with optional UDP support)
- **Lightweight** — Pure C, no external runtime dependencies, single binary
- **Multi-user** — Multiple agents connect simultaneously, routed by username
- **Portal Support** — Easy port forwarding over the proxy tunnel

## Building

### Prerequisites

- CMake >= 2.8
- C compiler (GCC / Clang / MSVC)
- Third-party libraries are bundled in `3rdparty/` (libuv, http-parser) — no extra installation needed

### Build Steps

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

The output is a single binary: `build/src/asterism/asterism` (or `asterism.exe` on Windows).

### Build with Unit Tests

```bash
mkdir build
cd build
cmake -DUNIT_TEST=ON ..
cmake --build . --config Debug
```

## Usage

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
  -A, --auth-sessions        Enable HTTP basic authentication for the session list (/sessions)
  -U, --session-user <user>  Username for the session list authentication
  -P, --session-pass <pass>  Password for the session list authentication
```

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

By default, this endpoint is public. You can enable HTTP Basic Authentication for `/sessions` using the `-A` / `--auth-sessions` flag, combined with `-U` / `--session-user` and `-P` / `--session-pass`:

```bash
# Start relay with sessions list authentication
asterism -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 -A -U admin -P admin123

# Query with credentials
curl -u admin:admin123 http://<relay_ip>:8081/sessions
```

## System Service Deployment

Asterism provides interactive installation scripts to register agent or relay modes as background daemons/tasks across multiple operating systems. This allows running both agent and relay instances on the same host under distinct names.

### Linux (systemd)
- **Install Service**: `sudo ./install/install_service.sh` (prompts for Mode and configuration).
- **Uninstall Service**: `sudo ./install/uninstall_service.sh` (prompts for which service to uninstall).
- **Service Names**: `asterism-relay.service` or `asterism-agent.service`
- **Installation Directory**: `/opt/asterism/` (shared binary directory)
- **Management Commands**:
  ```bash
  sudo systemctl status asterism-relay      # Check status
  sudo systemctl restart asterism-relay     # Restart service
  sudo journalctl -u asterism-relay -f      # View real-time logs
  ```

### macOS (launchd)
- **Install Service**: `sudo ./install/install_service_macos.sh` (prompts for Mode and configuration).
- **Uninstall Service**: `sudo ./install/uninstall_service_macos.sh` (prompts for which service to uninstall).
- **Service Labels**: `com.asterism.relay` or `com.asterism.agent`
- **Installation Location**: `/usr/local/bin/asterism` (shared binary)
- **Management Commands**:
  ```bash
  sudo launchctl list com.asterism.relay                     # Check status
  sudo launchctl unload /Library/LaunchDaemons/com.asterism.relay.plist  # Stop service
  tail -f /usr/local/var/log/com.asterism.relay/asterism.log     # View logs
  ```

### Windows (Task Scheduler)
- **Install Task**: Run `PowerShell` as Administrator, then: `.\install\install_task_windows.ps1` (prompts for Mode and configuration, sets task to run at boot under the `SYSTEM` account).
- **Uninstall Task**: `.\install\uninstall_task_windows.ps1`
- **Task Names**: `AsterismRelay` or `AsterismAgent`
- **Installation Directory**: `C:\Program Files\Asterism\` (shared binary directory)
- **Management Commands**:
  ```powershell
  schtasks /Query /TN AsterismRelay          # Check status
  schtasks /End /TN AsterismRelay            # Stop task
  schtasks /Run /TN AsterismRelay            # Start/Run task
  ```

## Project Structure

```
asterism/
├── 3rdparty/               # Third-party dependencies
│   ├── libuv/              # Cross-platform async I/O library
│   └── http-parser/        # HTTP protocol parser
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
│   └── test/               # Unit tests
├── install/                # Service installation scripts
├── CMakeLists.txt          # Build configuration
├── README.md               # English documentation
└── README_ZH.md            # Chinese documentation
```
