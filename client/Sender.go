package client

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Pinfo struct {
	SMac  net.HardwareAddr
	DMac  net.HardwareAddr
	SIp   net.IP
	DIp   net.IP
	SPort layers.TCPPort
	DPort layers.TCPPort
}

func sendSynP(c_interface string, pi chan Pinfo) {
	handle, err := pcap.OpenLive(c_interface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	fmt.Println("what wrong!")
	for {
		select {
		case p := <-pi:
			buf := BuildOnlySYNPacket(p.SMac, p.DMac, p.SIp, p.DIp, p.SPort, p.DPort)
			handle.WritePacketData(buf.Bytes())
			if err != nil {
				fmt.Println("send packet error")
			}
		}
		//fmt.Println("send sync done")
	}
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
