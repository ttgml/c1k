package client

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/arp"
)

func GetInterfaceHardwareAddr(deviceName string) (net.HardwareAddr, error) {
	ifs, err := net.InterfaceByName(deviceName)
	return ifs.HardwareAddr, err
}

func GetDestHardwareAddr(netdip net.IP, deviceName string) (net.HardwareAddr, error) {
	ifs, err := net.InterfaceByName(deviceName)
	dip, _ := netip.ParseAddr(netdip.String())
	arp_client, err := arp.Dial(ifs)
	arp_client.SetReadDeadline(time.UnixMilli(time.Now().UnixMilli() + 2000))
	err = arp_client.Request(dip)
	dmac := arp_client.HardwareAddr()
	for true {
		packet, _, err := arp_client.Read()
		if err != nil {
			return nil, err
		}
		if packet.SenderIP == dip {
			dmac = packet.SenderHardwareAddr
			break
		}
	}
	return dmac, err
}

func GetSubNetIpList(ips string, exclude string) ([]net.IP, error) {
	_, ipv4Net, err := net.ParseCIDR(ips)
	_, ex_ipv4Net, err := net.ParseCIDR(exclude)
	if err != nil {
		return nil, err
	}
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	ex_mask := binary.BigEndian.Uint32(ex_ipv4Net.Mask)
	ex_start := binary.BigEndian.Uint32(ex_ipv4Net.IP)

	var result []net.IP
	var ex_result []net.IP
	finish := (start & mask) | (mask ^ 0xffffffff)
	ex_finish := (ex_start & ex_mask) | (ex_mask ^ 0xffffffff)
	for i := ex_start; i <= ex_finish; i++ {
		ex_ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ex_ip, i)
		ex_result = append(ex_result, ex_ip)
	}
	for i := start; i <= finish; i++ {
		have := false
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		for _, i := range ex_result {
			if ip.Equal(i) {
				have = true
			}
		}
		if !have {
			result = append(result, ip)
		}
	}
	if len(result) < 3 {
		return result, err
	}
	return result[1 : len(result)-1], err

}

func checkSrcPortRange(srcRange string) error {
	port_start := strings.Split(srcRange, "-")[0]
	port_end := strings.Split(srcRange, "-")[1]
	ps, err := strconv.Atoi(port_start)
	pe, err := strconv.Atoi(port_end)
	if err != nil {
		return err
	}
	if (ps-pe > 1) && pe < 65535 && ps > 1 {
		return nil
	} else {
		return errors.New("src port range error")
	}
}
