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
asterism -r
