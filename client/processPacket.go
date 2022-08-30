package client

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ProcessTask(c_src_hosts string, c_interface string, c_host string, sports string, c_src_exclude_hosts string, dport int, count int, wg *sync.WaitGroup) error {
	if strings.Contains(c_src_hosts, "/") {
		//输入的源host包含掩码，是一个网段
		// src_ip, src_ipnet, err:=net.ParseCIDR(c_src_hosts)
		// if err != nil{
		// 	fmt.Println("src ip format error")
		// 	os.Exit(1)
		// }
		// fmt.Println("src ip and ipnet: ",src_ip, src_ipnet)
	} else {
		c_src_hosts = c_src_hosts + "/32"
	}
	s_mac, err := GetInterfaceHardwareAddr(c_interface)
	if err != nil {
		fmt.Println("interface error")
	}
	// fmt.Println("s_mac: ", s_mac)
	dip := net.ParseIP(c_host)
	// fmt.Println("d_ip: ", dip)
	d_mac, err := GetDestHardwareAddr(dip, c_interface)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// fmt.Println("d_mac: ", d_mac)

	var record int = 0
	port_start, err := strconv.Atoi(strings.Split(sports, "-")[0])
	port_end, err := strconv.Atoi(strings.Split(sports, "-")[1])
	if err != nil {
		return err
	}
	// fmt.Println("port start-end: ", port_start, port_end)
	sips, err := GetSubNetIpList(c_src_hosts, c_src_exclude_hosts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// fmt.Println(sips)

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
			// fmt.Println(sip, i)
			//fmt.Println(s_mac, d_mac, sip, dip, layers.TCPPort(uint16(i)), layers.TCPPort(uint16(dport)))
			buf := BuildOnlySYNPacket(s_mac, d_mac, sip, dip, layers.TCPPort(uint16(i)), layers.TCPPort(uint16(dport)))
			handle.WritePacketData(buf.Bytes())
			if err != nil {
				fmt.Println("send packet error")
			}
			// fmt.Println("send done.")
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
	fmt.Println("Task Done.")
	wg.Done()
	return nil
}

func BuildOnlySYNPacket(smac net.HardwareAddr, dmac net.HardwareAddr, sip net.IP, dip net.IP, sport layers.TCPPort, dport layers.TCPPort) gopacket.SerializeBuffer {
	eth := layers.Ethernet{
		SrcMAC:       smac,
		DstMAC:       dmac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    sip,
		DstIP:    dip,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: sport,
		DstPort: dport,
		ACK:     false,
		SYN:     true,
		Window:  65280,
		Seq:     10000,
	}
	err := tcpLayer.SetNetworkLayerForChecksum(&ipLayer)
	if err != nil {
		panic(err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &eth, &ipLayer, &tcpLayer)
	if err != nil {
		panic(err)
	}
	return buf
}
