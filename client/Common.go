package client

import (
	"encoding/binary"
	"fmt"
	"github.com/mdlayher/arp"
	"net"
	"net/netip"
	"time"
)

func GetInterfaceHardwareAddr(deviceName string) (net.HardwareAddr, error){
	ifs, err := net.InterfaceByName(deviceName)
	return ifs.HardwareAddr,err
}

func GetDestHardwareAddr(netdip net.IP, deviceName string) (net.HardwareAddr, error){
	ifs, err := net.InterfaceByName(deviceName)
	dip, _ := netip.ParseAddr(netdip.String())
	arp_client, err := arp.Dial(ifs)
	arp_client.SetReadDeadline(time.UnixMilli(time.Now().UnixMilli()+2000))
	err = arp_client.Request(dip)
	dmac:=arp_client.HardwareAddr()
	for true {
		packet, _, err := arp_client.Read()
		if err != nil{
			fmt.Println(err)
			return nil, err
		}
		if packet.SenderIP == dip {
			dmac = packet.SenderHardwareAddr
			break
		}
	}
	return dmac,err
}

func GetSubNetIpList(ips string, exclude string) ([]net.IP,error){
	_, ipv4Net, err := net.ParseCIDR(ips)
	fmt.Println(ipv4Net)
	_, ex_ipv4Net, err:= net.ParseCIDR(exclude)
	if err != nil {
		return nil, err
	}
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	ex_mask :=binary.BigEndian.Uint32(ex_ipv4Net.Mask)
	ex_start := binary.BigEndian.Uint32(ex_ipv4Net.IP)

	var result []net.IP
	var ex_result []net.IP
	finish := (start & mask) | (mask ^ 0xffffffff)
	ex_finish := (ex_start & ex_mask) | (ex_mask ^ 0xffffffff)
	for i := ex_start; i<=ex_finish;i++{
		ex_ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ex_ip, i)
		ex_result = append(ex_result,ex_ip)
	}
	fmt.Println("aa: ", ex_result)
	for i := start; i <= finish; i++ {
		have := false
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		for _, i := range ex_result{
			if ip.Equal(i) {
				have = true
			}
		}
		if !have{
			result = append(result, ip)
		}
	}
	fmt.Println("len result: ", len(result))
	if len(result)<3{
		return result,err
	}
	return result[1:len(result)-1], err

}