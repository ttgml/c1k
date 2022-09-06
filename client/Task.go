package client

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket/layers"
)

var wg sync.WaitGroup
var Pi_channel = make(chan Pinfo, 10000) //需要发包的队列
var C_interface string
var C_src_hosts string
var C_host string
var C_src_port_range string
var C_src_exclude_hosts string
var C_count int
var C_rate int32
var C_port layers.TCPPort
var C_keepalive bool = true
var mapPshList = make(map[PshKey]PshValue)
var mapPshListSync sync.Map

type PshKey struct {
	Ip   string
	Port uint16
}
type PshValue struct {
	Seq uint32
	Ack uint32
}

func StartTask(c_interface string, c_port int, c_src_hosts string, c_host string, c_src_port_range string, c_src_exclude_hosts string, c_count int, c_rate int32) error {
	sd_channel := make(chan int, 10000)  //发送SYN(1)后记录一下
	est_channel := make(chan int, 10000) //发送ACK(3)后记录一下
	rst_channel := make(chan int, 10000) //接收到rst包需要记录一下
	re_channel := make(chan int, 10000)  //接受到目标发送过来的包(只要发包就算) //用于确定进度
	C_interface = c_interface
	C_src_hosts = c_src_hosts
	C_host = c_host
	C_src_port_range = c_src_port_range
	C_src_exclude_hosts = c_src_exclude_hosts
	C_count = c_count
	C_rate = c_rate
	C_port = layers.TCPPort(uint16(c_port))
	// var rst_count int = 0

	//检查参数
	err := checkSrcPortRange(c_src_port_range)
	if err != nil {
		fmt.Println("params error")
		return err
	}

	//已经发送的包记数（不确定连接是否建立）
	var sd_count int = 0
	var rst_count int = 0
	var est_count int = 0
	var re_count int = 0
	wg.Add(1)
	//抓包
	fmt.Println("go hander packet")
	go HanderPacket(c_interface, c_port, &wg, est_channel, rst_channel, re_channel)
	wg.Wait() //等待网卡，需要点时间

	//启动一个goroutine 处理连接保活
	if C_keepalive {
		fmt.Println("need keep alive.")
		wg.Add(1) //如果指定了keepalive，需要一直持续运行
		go KeepAlive()
		fmt.Println("keepAlive load...")
	}

	fmt.Println("hander packet load...")
	go sum_rst_connect(rst_channel, &rst_count)
	go sum_send_connect(sd_channel, &sd_count)
	go sum_est_connect(est_channel, &est_count)
	go sum_re_connect(re_channel, &re_count)

	wg.Add(1)
	//go ProcessTask(c_src_hosts, c_interface, c_host, c_src_port_range, c_src_exclude_hosts, c_port, c_count, &wg, sd_channel)
	go sendSynP(c_interface, Pi_channel)
	fmt.Println("sendSyncP load...")
	go RateControl(&wg)
	fmt.Println("rateControl load...")
	//for {
	//	select {
	//	case <-re_channel:
	//		fmt.Println(sd_count, est_count, rst_count, c_count, re_count)
	//	}
	//	fmt.Println(est_count + rst_count)
	//	if sd_count == (est_count + rst_count) {
	//		fmt.Println(sd_count, est_count, rst_count, re_count)
	//		break
	//	}
	//}

	wg.Wait() //等待发包结束/持续等待KeepAlive
	return nil
}

func sum_rst_connect(rst_channel chan int, rst_count *int) {
	for {
		select {
		case <-rst_channel:
			*rst_count++
		}
	}
}

func sum_send_connect(sd_channel chan int, sd_count *int) {
	for {
		select {
		case <-sd_channel:
			*sd_count++
		}
	}
}

func sum_est_connect(est_channel chan int, est_count *int) {
	for {
		select {
		case <-est_channel:
			*est_count++
		}
	}
}

func sum_re_connect(re_channel chan int, re_count *int) {
	for {
		select {
		case <-re_channel:
			*re_count++
		}
	}
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
