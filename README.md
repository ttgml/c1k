# C1K

定位是一个辅助测试工具。

一般在验证负载均衡性能和配置的时候会用到，主要用于模拟建立大量长连接。

### 实现原理
通过抓取网卡数据包，并且解析TCP协议报文数据。当匹配到建立连接的SYN报文时，模拟正常连接进行回包，让客户端认为连接已经建立。

这个程序并不会去维护连接，只是根据报文返回与之对应的报文，所以程序运行时资源占用不多。

抓取数据包需要ROOT权限，所以在运行时需要以ROOT用户运行。


### 使用方法

#### 前期准备
服务端
```shell
sudo iptables-legacy -A INPUT -p tcp --dport <target port> -j DROP
```

客户端
```shell
sudo iptables-legacy -A INPUT -p tcp --dport 10000:60000 -j DROP
```

为什么要加防火墙规则，系统防火墙默认检测到没有开放的端口，会自动发送一个RST的报文，这个报文会时连接中断。
所以添加防火墙规则，可以阻止系统发送RST报文。

