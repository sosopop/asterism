const net = require("net");
const http = require("http");
const fs = require("fs");

class Config {
    constructor(configPath = 'config.json') {
        const configJson = fs.readFileSync(configPath, "utf-8");
        this.configObj = JSON.parse(configJson);
    }

    getConfig() {
        return this.configObj;
    }
}

class Portal {
    constructor(config) {
        this.name = config.name;
        this.relayHost = config.relayHost;
        this.relayPort = config.relayPort;
        this.username = config.username;
        this.password = config.password;
        this.targetHost = config.targetHost;
        this.targetPort = config.targetPort;
        this.localHost = config.localHost;
        this.localPort = config.localPort;

        this.server = net.createServer((inSocket) => {
            console.log(`Portal: client connected, tunneling via relay ${this.relayHost}:${this.relayPort}`);
            inSocket.pause();

            const req = http.request({
                host: this.relayHost,
                port: this.relayPort,
                method: "CONNECT",
                path: `${this.targetHost}:${this.targetPort}`,
                headers: {
                    "Proxy-Authorization": `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`,
                },
            });
            req.end();
            req.on("connect", (res, sock, head) => {
                console.log(`Portal: tunnel established to ${this.targetHost}:${this.targetPort} via relay ${this.relayHost}:${this.relayPort}`);
                sock.on("close", () => {
                    console.log(`Portal: tunnel to ${this.targetHost}:${this.targetPort} closed`);
                    inSocket.destroy();
                });
                sock.on("error", () => {
                    console.log(`Portal: tunnel error on ${this.targetHost}:${this.targetPort}`);
                });
                inSocket.resume();
                inSocket.pipe(sock);
                sock.pipe(inSocket);
            });
            req.on("error", (e) => {
                console.log(`Portal: relay connection error on ${this.relayHost}:${this.relayPort}`);
                inSocket.destroy();
            });
            inSocket.on("close", () => {
                console.log(`Portal: client disconnected`);
                req.destroy();
            });
            inSocket.on("error", (e) => {
                console.log(`Portal: client connection error`);
                req.destroy();
            });
        });

        this.server.on("error", (err) => {
            console.log(`Portal error on ${this.relayHost}:${this.relayPort}: ${err}`);
        });
    }

    connect() {
        this.server.listen(
            {
                host: this.localHost,
                port: this.localPort,
            },
            () => {
                console.log(`Portal "${this.name}" listening on ${this.localHost}:${this.localPort} -> ${this.targetHost}:${this.targetPort} via relay ${this.relayHost}:${this.relayPort}`);
            }
        );
    }

    getConnectionStatus() {
        return this.server.listening;
    }

    disconnect() {
        this.server.close();
    }

    setConnectionCallback(callback) {
        this.server.on("listening", callback);
    }
}

// Usage example
const configPath = process.argv[2]; // Will be undefined if not provided
const config = new Config(configPath).getConfig();
const portals = config.map((conf) => {
    const portal = new Portal(conf);

    portal.setConnectionCallback(() => {
        console.log(`Portal "${conf.name}" connected via relay ${conf.relayHost}:${conf.relayPort}`);
    });

    portal.connect();

    return portal;
});
