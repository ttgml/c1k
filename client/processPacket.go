package client

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ProcessTask(c_src_hosts string, c_interface string, c_host string, sports string, c_src_exclude_hosts string, dport int, count int, wg *sync.WaitGroup, sd chan int) error {
	if strings.Contains(c_src_hosts, "/") {
		//输入的源host包含掩码，是一个网段
	} else {
		c_src_hosts = c_src_hosts + "/32"
	}
	s_mac, err := GetInterfaceHardwareAddr(c_interface)
	if err != nil {
		fmt.Println("interface error")
	}
	dip := net.ParseIP(c_host)
	d_mac, err := GetDestHardwareAddr(dip, c_interface)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var record int = 0
	port_start, err := strconv.Atoi(strings.Split(sports, "-")[0])
	port_end, err := strconv.Atoi(strings.Split(sports, "-")[1])
	if err != nil {
		return err
	}
	sips, err := GetSubNetIpList(c_src_hosts, c_src_exclude_hosts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(c_interface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	next := true
	ps := port_start
	for _, sip := range sips {
		if !next {
			break
		}
		for i := ps; i < port_end; i++ {
			buf := BuildOnlySYNPacket(s_mac, d_mac, sip, dip, layers.TCPPort(uint16(i)), layers.TCPPort(uint16(dport)))
			handle.WritePacketData(buf.Bytes())
			if err != nil {
				fmt.Println("send packet error")
			}
			sd <- 1
			record = record + 1
			time.Sleep(time.Microsecond * 100)
			if record >= count {
				next = false
			}
			if !next {
				break
			}
		}
	}
	wg.Done()
	return nil
}
