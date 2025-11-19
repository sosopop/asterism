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

class ProxyServer {
    constructor(config) {
        this.name = config.name;
        this.proxyHost = config.proxyHost;
        this.proxyPort = config.proxyPort;
        this.proxyUsername = config.proxyUsername;
        this.proxyPassword = config.proxyPassword;
        this.targetHost = config.targetHost;
        this.targetPort = config.targetPort;
        this.localHost = config.localHost;
        this.localPort = config.localPort;

        this.server = net.createServer((inSocket) => {
            console.log(`client connected to proxy ${this.proxyHost}:${this.proxyPort}`);
            inSocket.pause();

            const req = http.request({
                host: this.proxyHost,
                port: this.proxyPort,
                method: "CONNECT",
                path: `${this.targetHost}:${this.targetPort}`,
                headers: {
                    "Proxy-Authorization": `Basic ${Buffer.from(`${this.proxyUsername}:${this.proxyPassword}`).toString("base64")}`,
                },
            });
            req.end();
            req.on("connect", (res, sock, head) => {
                console.log(`Connected to target ${this.targetHost}:${this.targetPort} via proxy ${this.proxyHost}:${this.proxyPort}`);
                sock.on("close", () => {
                    console.log(`Connection to target ${this.targetHost}:${this.targetPort} closed on proxy ${this.proxyHost}:${this.proxyPort}`);
                    inSocket.destroy();
                });
                sock.on("error", () => {
                    console.log(`Error occurred on target ${this.targetHost}:${this.targetPort} connection on proxy ${this.proxyHost}:${this.proxyPort}`);
                });
                inSocket.resume();
                inSocket.pipe(sock);
                sock.pipe(inSocket);
            });
            req.on("error", (e) => {
                console.log(`Error occurred on proxy ${this.proxyHost}:${this.proxyPort} connection`);
                inSocket.destroy();
            });
            inSocket.on("close", () => {
                console.log(`Client disconnected from proxy ${this.proxyHost}:${this.proxyPort}`);
                req.destroy();
            });
            inSocket.on("error", (e) => {
                console.log(`Error occurred on client connection on proxy ${this.proxyHost}:${this.proxyPort}`);
                req.destroy();
            });
        });

        this.server.on("error", (err) => {
            console.log(`Error occurred on proxy ${this.proxyHost}:${this.proxyPort}: ${err}`);
        });
    }

    connect() {
        this.server.listen(
            {
                host: this.localHost,
                port: this.localPort,
            },
            () => {
                console.log(`Server bound to ${this.name} ${this.localHost}:${this.localPort} on proxy ${this.proxyHost}:${this.proxyPort}`);
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
const proxies = config.map((conf) => {
    const proxy = new ProxyServer(conf);

    proxy.setConnectionCallback(() => {
        console.log(`Proxy server (${conf.proxyHost}:${conf.proxyPort}) connected`);
    });

    proxy.connect();

    return proxy;
});
