# C1K

定位是一个辅助测试工具。

一般在验证负载均衡性能和配置的时候会用到，主要用于模拟建立大量长连接。

### 实现原理
通过抓取网卡数据包，并且解析TCP协议报文数据。当匹配到建立连接的SYN报文时，模拟正常连接进行回包，让客户端认为连接已经建立。

这个程序并不会去维护连接，只是根据报文返回与之对应的报文，所以程序运行时资源占用不多。

抓取数据包需要ROOT权限，所以在运行时需要以ROOT用户运行。


### 使用方法

#### 前期准备
在客户端和服务端机器分别执行下面两个命令，这两条命令设置防火墙策略，丢弃系统发送RST报文。
```shell
sudo iptables-legacy -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
sudo iptables-legacy -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
```

### TODO
心跳问题
    客户端需要在一定时间内保持连接不断开，需要有心跳机制