# asterism
A solution that exposes the client's service interface to the server or other client through proxy

qq:12178761
wx:mengchao1102

Usage example:
    asterism [(-h|--help)] [(-v|--verbose)] [(-V|--version)] [(-i|--in-addr) string] [(-o|--out-addr) string] [(-r|--remote-addr) string] [(-u|--user) string] [(-p|--pass) string]
    asterism.exe -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 -v
    asterism.exe -r tcp://127.0.0.1:1234 -usosopop -p12345678 -v

Options:
    -h or --help: Displays this information.
    -v or --verbose: Verbose mode on.
    -V or --version: Displays the current version number.
    -i or --in-addr string: Server local proxy listen address, example: -i http://0.0.0.0:8080
    -o or --out-addr string: Server remote listen address, example: -i tcp://0.0.0.0:1234
    -r or --remote-addr string: Client connect to address, example: -i tcp://1.1.1.1:1234
    -u or --user string: Client username for Server authorization.
    -p or --pass string: Client password for Server authorization.
