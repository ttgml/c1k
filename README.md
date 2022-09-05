# C1K

定位是一个辅助测试工具。

1. 一般在验证负载均衡性能和配置的时候会用到，主要模拟建立大量长连接。 
2. 支持指定总连接数量和每秒新建连接数，TCP连接支持心跳保活。
3. 可以自定义任意源IP范围和任意端口范围

### 实现原理
**服务端**

直接抓取网卡数据包，解析TCP协议数据包，匹配到建立连接的报文后，模拟TCP协议进行握手建立连接。

**客户端**

构建正常的TCP握手包，直接通过网卡发送。同时抓取网卡数据包，检测到TCP握手相关的数据包时，根据TCP协议返回对应的数据包，以完成握手。

整个完整过程，程序都不会去维护连接(只有在开启KeepAlive时会记录源IP/端口/seq/ack)，都是根据收到的报文返回与之对应的握手或者ACK报文，所以程序运行时资源占用不多，理论上可以支持创建很多很多长连接。


### 使用方法

#### 前期准备
0. 网络拓扑图，准备三台机器，一台客户机(创建连接)，一台服务机(模拟处理连接)，一台负载均衡(被测试)

```sequence
Clients->LBS: Connect to
LBS-> Servers:  Reverse proxy
Servers -> LBS: Connection establishment;
LBS->Clients: Connection establishment
```

1. 在客户机和服务机分别执行下面两个命令，这两条命令设置防火墙策略，丢弃系统发送RST报文。
```shell
sudo iptables-legacy -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
sudo iptables-legacy -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
```
2. 在负载均衡上设置默认路由，指向Clients的地址
```shell
sudo ip route add default via <client_ip>
```
3. 在后端服务器上启动server
```shell
sudo ./c1k server -i <interface> -x <ip> -p <port>
```

4. 在客户端机器上启动client
```client
sudo ./c1k client -i <interface> -x <ip> -p <port> -s <cidr> -b <src_port_range> -c <count>
```

### 参数说明
#### server
 -  ` --host / -x ` 指定后端服务的IP
 -  ` --interface / -i ` 指定抓包网卡名字
 -  ` --port / -p ` 指定服务端口，可以同时指定多个端口(用英文逗号分割)。
#### client
 - ` --host / -x ` 指定服务IP（通常为负载均衡的IP)
 - ` --port / -p ` 指定服务器端口 (通常为负载均衡的端口)
 - ` --interface / -i ` 指定发包网卡名字
 - ` --count / -c ` 指定连接数
 - ` --rate / -r ` 指定新建连接速率，单位为 次数/秒
 - ` --srcport / -b ` 指定源端口范围，如2000-62000
 - ` --src / -s ` 指定源IP，可以为地址范围，如 192.168.56.1/24 
 - ` --exclude / -e ` 排除某些源地址，格式如src
 - ` --keepalive / -k ` 开启KeepAlive功能，定时发送心跳包，默认不指定(不开启)。

### TODO
心跳问题

- ~~客户端需要在一定时间内保持连接不断开，客户端需要有心跳机制(PSH+ACK)~~

统计功能

 - 需要统计已经建立的连接数
 - 连接成功率
 - 需要记录失败的端口

控制速率

 - ~~指定每秒新建连接数~~
 - 支持慢启动

控制带宽