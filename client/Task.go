package client

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

var wg sync.WaitGroup
var Pi_channel = make(chan Pinfo, 10000) //需要发包的队列，由Control控制这个队列，然后 Sender.go 收到消息后，发包。
var C_interface string                   //接口名
var C_src_hosts string                   //源地址
var C_host string                        //目的地址
var C_src_port_range string              //源端口
var C_src_exclude_hosts string           //排除的IP
var C_count int                          //需要发起请求的总数
var C_rate int32                         //速率
var C_port layers.TCPPort                //目的端口
var C_keepalive bool                     //是否开启心跳
var mapPshListSync sync.Map              //心跳记录
var C_keep_count int64 = 0

//已经发送的包记数（不确定连接是否建立）
// 发送SYN的数量
var sd_count int = 0

// 记录RST的数量
var rst_count int = 0

// 记录EST的数量
var est_count int = 0

type PshKey struct {
	Ip   string
	Port uint16
}
type PshValue struct {
	Seq uint32
	Ack uint32
}

func StartTask(c_interface string, c_port int, c_src_hosts string, c_host string, c_src_port_range string, c_src_exclude_hosts string, c_count int, c_rate int32, c_keepalive bool) error {
	C_interface = c_interface
	C_src_hosts = c_src_hosts
	C_host = c_host
	C_src_port_range = c_src_port_range
	C_src_exclude_hosts = c_src_exclude_hosts
	C_count = c_count
	C_rate = c_rate
	C_port = layers.TCPPort(uint16(c_port))
	C_keepalive = c_keepalive

	//检查参数
	err := checkSrcPortRange(c_src_port_range)
	if err != nil {
		fmt.Println(err)
		fmt.Println("params error")
		return err
	}

	//抓包
	wg.Add(1)
	go HanderPacket(&wg)
	wg.Wait() //等待网卡，需要点时间

	//启动一个goroutine 处理连接保活
	if C_keepalive {
		wg.Add(1) //如果指定了keepalive，需要一直持续运行
		go KeepAlive()
	}

	wg.Add(1)
	go sendSynP(c_interface, Pi_channel)
	go RateControl(&wg)

	go PrintTaskProcess()

	wg.Wait() //等待发包结束/持续等待KeepAlive
	return nil
}

func ParseSynBaseInfo() (Pinfo, []net.IP, int, int, error) {
	var base_pi Pinfo

	//需要准备信息、解析源地址范围、源端口范围、获取MAC地址
	if !strings.Contains(C_src_hosts, "/") {
		C_src_hosts = C_src_hosts + "/32"
	}
	s_mac, err := GetInterfaceHardwareAddr(C_interface)
	if err != nil {
		fmt.Println("interface error")
	}
	dip := net.ParseIP(C_host)
	d_mac, err := GetDestHardwareAddr(dip, C_interface)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	port_start, err := strconv.Atoi(strings.Split(C_src_port_range, "-")[0])
	port_end, err := strconv.Atoi(strings.Split(C_src_port_range, "-")[1])
	if err != nil {
		return base_pi, nil, 0, 0, err
	}
	sips, err := GetSubNetIpList(C_src_hosts, C_src_exclude_hosts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	base_pi.SMac = s_mac
	base_pi.DMac = d_mac
	base_pi.DIp = dip
	base_pi.DPort = C_port
	return base_pi, sips, port_start, port_end, nil
}

func PrintTaskProcess() {
	for true {
		time.Sleep(1 * time.Second)
		if C_keepalive {
			len := 0
			mapPshListSync.Range(func(k, v interface{}) bool {
				len++
				fmt.Println(k, v)
				return true
			})

			fmt.Println(sd_count, est_count, rst_count, len, C_keep_count)
		} else {
			fmt.Println(sd_count, est_count, rst_count)
		}
	}

}
