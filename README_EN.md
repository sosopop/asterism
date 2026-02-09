# ✦ Asterism

English | [中文](README.md)

Asterism is a lightweight reverse proxy for intranet penetration (NAT traversal). It exposes services behind NAT/firewalls to the public network through a relay server with a public IP, enabling external users to access TCP and HTTP services on private networks.

Typical use cases:

- Remotely access a home NAS or router admin panel
- Connect to office RDP, SSH, or other internal services
- Server-to-client message pushing (client hosts a Web API for the server to call)

## Features

- **Cross-platform** — Windows, Linux, macOS, Android, iOS
- **High performance** — Event-driven architecture built on libuv async I/O
- **Protocol support** — HTTP proxy, SOCKS5 proxy (with optional UDP support)
- **Lightweight** — Pure C, no external runtime dependencies, single binary
- **Multi-user** — Multiple clients connect simultaneously, routed by username

## Architecture Overview

```mermaid
graph LR
    subgraph Public_Network [Public Network]
        Visitor["Visitor<br>(Browser / curl)"]
    end

    subgraph Asterism_Server ["Asterism Server (Relay)"]
        direction TB
        Proxy["HTTP Proxy :8081<br>SOCKS5 Proxy :8082"]
        Outer["Outer TCP :1234"]
        Proxy -.-> Outer
    end

    subgraph Private_Network [Private Network]
        Client["Asterism Client<br>(Connector)"]
        Services["LAN Services<br>(NAS, RDP, SSH, Web...)"]
    end

    Visitor --> Proxy
    Outer <-->|Persistent Connection| Client
    Client --> Services

    style Public_Network fill:#f9f,stroke:#333,stroke-width:2px
    style Asterism_Server fill:#bbf,stroke:#333,stroke-width:2px
    style Private_Network fill:#bfb,stroke:#333,stroke-width:2px
```

**How it works:**

1. The **Client** connects to the Server's Outer port, authenticates with username/password, and establishes a persistent tunnel
2. The **Server** listens for proxy requests (HTTP/SOCKS5) on Inner ports, waiting for visitors
3. A **Visitor** connects to the Server via proxy protocol, specifying the target client's credentials
4. The **Server** forwards the request through the tunnel to the corresponding client, which accesses local/LAN services and returns the response

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
make
```

The output is a single binary: `build/src/asterism/asterism`

### Build with Unit Tests

```bash
mkdir build
cd build
cmake -DUNIT_TEST=ON ..
make
```

## Usage

### Command-Line Options

```
asterism [options]

Options:
  -h, --help                 Show help message
  -v, --verbose              Enable debug log output
  -V, --version              Display version number
  -i, --in-addr <address>    Server proxy listen address (can be specified multiple times)
                             Example: -i http://0.0.0.0:8081
                             Example: -i socks5://0.0.0.0:8082
  -o, --out-addr <address>   Server outer listen address (for client connections)
                             Example: -o tcp://0.0.0.0:1234
  -r, --remote-addr <address> Client connection address to server
                             Example: -r tcp://1.2.3.4:1234
  -u, --user <username>      Client authentication username
  -p, --pass <password>      Client authentication password
  -d, --udp                  Enable SOCKS5 UDP support (disabled by default)
  -t, --udp-timeout <seconds> UDP session idle timeout (0 = no timeout)
```

### Quick Start

**Step 1: Start the Server** (on a machine with a public IP)

```bash
asterism \
  -i http://0.0.0.0:8081 \
  -i socks5://0.0.0.0:8082 \
  -o tcp://0.0.0.0:1234 \
  -v
```

- `-i` sets proxy listen addresses; HTTP and SOCKS5 can run simultaneously
- `-o` sets the port for client connections

**Step 2: Start the Client** (on a machine behind NAT)

```bash
asterism \
  -r tcp://<server_ip>:1234 \
  -u myuser \
  -p mypassword \
  -v
```

The client automatically connects to the server and maintains the tunnel, reconnecting every 10 seconds if disconnected.

**Step 3: Access LAN services through the proxy**

```bash
# Via HTTP proxy
curl "http://192.168.1.100:8080/api" \
  --proxy "http://<server_ip>:8081" \
  --proxy-user "myuser:mypassword"

# Via SOCKS5 proxy
curl "http://192.168.1.100:8080/api" \
  --proxy "socks5://<server_ip>:8082" \
  --proxy-user "myuser:mypassword"
```

### Multi-Client Scenario

Multiple clients behind different NATs can connect to the same server simultaneously, each identified by a unique username. Visitors route to different clients by specifying different credentials, accessing each client's local network resources.

```bash
# Client A (home network)
asterism -r tcp://server:1234 -u home -p pass_a -v

# Client B (office network)
asterism -r tcp://server:1234 -u office -p pass_b -v

# Access NAS on home network
curl http://192.168.1.10:5000 --proxy socks5://server:8082 --proxy-user "home:pass_a"

# Access remote desktop on office network
curl http://10.0.0.50:3389 --proxy socks5://server:8082 --proxy-user "office:pass_b"
```

## System Service Deployment (Linux)

The project includes systemd service scripts to run Asterism as a background daemon:

```bash
# Install service (requires root)
sudo ./install/install_service.sh

# Uninstall service
sudo ./install/uninstall_service.sh
```

Common management commands after installation:

```bash
sudo systemctl status asterism     # Check status
sudo systemctl start asterism      # Start service
sudo systemctl stop asterism       # Stop service
sudo systemctl restart asterism    # Restart service
sudo journalctl -u asterism -f     # View logs in real time
```

The service is installed to `/opt/asterism/` by default. Runtime parameters are configured in `/etc/systemd/system/asterism.service`.

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
│   ├── asterism_outer_*    # Outer connection listener (client connections)
│   ├── asterism_connector_*# Client-side connector
│   ├── asterism_requestor_*# Request forwarding
│   ├── asterism_responser_*# Response forwarding
│   └── test/               # Unit tests
├── install/                # systemd service installation scripts
├── doc/                    # Documentation resources
├── CMakeLists.txt          # Build configuration
└── README.md
```
