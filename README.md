# C1K

定位是一个辅助测试工具。

一般在验证负载均衡性能和配置的时候会用到，主要用于模拟建立大量长连接。

### 实现原理
通过抓取网卡数据包，并且解析TCP协议报文数据。当匹配到建立连接的SYN报文时，模拟正常连接进行回包，让负载均衡认为连接已经建立。

程序并不会去维护连接，只是根据报文返回与之对应的报文，所以程序运行时资源占用不多。

抓取数据包需要ROOT权限，所以在运行时需要以ROOT用户运行。


### 使用方法

#### 前期准备
0. 网络拓扑图

```sequence
Clients->LBS: Connect to
LBS-> Servers: Connect to
Servers -> LBS: Connection establishment;
LBS->Clients: Connection establishment
```

1. 在客户端和服务端机器分别执行下面两个命令，这两条命令设置防火墙策略，丢弃系统发送RST报文。
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
 - ` --srcport / -b ` 指定源端口范围，如2000-62000>
 - ` --src / -s ` 指定源IP，可以为地址范围，如 192.168.56.1/24 
 - ` --exclude / -e ` 排除某些源地址

### TODO
心跳问题

- 客户端需要在一定时间内保持连接不断开，客户端需要有心跳机制(PSH+ACK)

统计功能

 - 需要统计已经建立的连接数
 - 连接成功率
 - 需要记录失败的端口

控制速率

 - 指定每秒新建连接数

控制带宽

