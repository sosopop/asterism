# asterism
内网穿透的反向代理,可以用于访问没有公网ip客户端的各种基于tcp,http的服务程序,比如家里的nas,公司电脑的远程桌面等等,也可以用于服务器对客户端的消息推送,客户端建立webapi服务,给服务器调用<br>
<br>
特点:<br>
跨平台,高性能,轻量,支持socks5和http代理.<br>
<br>
支持平台:<br>
windows linux osx android ios<br>
<br>
email:12178761@qq.com<br>
qq:12178761<br>
wx:mengchao1102<br>
如果您感觉对您有所帮助，press star please

<br>
编译:<br>
<br>
mkdir build<br>
cd build<br>
cmake ..<br>
make<br>
./src/asterism/asterism --help<br>
<br>
运行方式:<br>
转发者(有公网ip):<br>
asterism -i http://0.0.0.0:8081 -i socks5://0.0.0.0:8082 -o tcp://0.0.0.0:1234 -v<br>
<br>
服务提供者(没有公网ip):<br>
asterism -r tcp://(server ip):1234 -usosopop -p12345678 -v<br>	asterism -r
<br>	
访问者(用户名密码为服务提供者配置的):<br>	
curl "http://vv.video.qq.com/checktime" --proxy "http://(server ip):8081" --proxy-user "sosopop:12345678"<br>	
or<br>	
curl "http://vv.video.qq.com/checktime" --proxy "socks5://(server ip):8082" --proxy-user "sosopop:12345678"<br>	
<br>	
说明:<br>	
用户名密码为服务提供者配置的,服务提供者可以有多个,使用不同的用户名进行区别,访问者使用不同的用户名密码,去连接不同的服务提供者,从而可以访问服务提供者的所有本机和内网资源.<br>	
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
