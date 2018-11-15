# asterism
A solution that exposes the client's service interface to the server or other client through proxy<br>
<br>
qq:12178761<br>
wx:mengchao1102<br>
<br>
Usage example:<br>
    asterism [(-h|--help)] [(-v|--verbose)] [(-V|--version)] [(-i|--in-addr) string] [(-o|--out-addr) string] [(-r|--remote-addr) string] [(-u|--user) string] [(-p|--pass) string]<br>
    asterism.exe -i http://0.0.0.0:8081 -i socks5://0.0.0.0:8082 -o tcp://0.0.0.0:1234 -v<br>
    asterism.exe -r tcp://127.0.0.1:1234 -usosopop -p12345678 -v<br>
<br>
Options:<br>
    -h or --help: Displays this information.<br>
    -v or --verbose: Verbose mode on.<br>
    -V or --version: Displays the current version number.<br>
    -i or --in-addr string: Server local proxy listen address, example: -i http://0.0.0.0:8080<br>
    -o or --out-addr string: Server remote listen address, example: -i tcp://0.0.0.0:1234<br>
    -r or --remote-addr string: Client connect to address, example: -i tcp://1.1.1.1:1234<br>
    -u or --user string: Client username for Server authorization.<br>
    -p or --pass string: Client password for Server authorization.<br>
