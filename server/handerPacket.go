package server

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"net"
	"strings"
)

//这个方法主要用来抓取数据包，以及模拟建立连接和端开连接(SYN+FIN)
func HanderPacket(deviceName string, host string, port string) {
	var s_host net.IP = net.ParseIP(host)
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	filter := "dst host " + s_host.String()
	for i, p := range strings.Split(port, ",") {
		fmt.Println(i, p)
		if i == 0 {
			filter = filter + " and port " + string(p)
		} else {
			filter = filter + " or port " + string(p)
		}
	}
	handle.SetBPFFilter(filter)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			continue
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			// fmt.Println("SYN: ",tcp.SYN,tcp.ACK,tcp.PSH,tcp.FIN)
			var linklayer []byte = packet.LinkLayer().LayerContents()
			var d_mac net.HardwareAddr = linklayer[0:6]
			var s_mac net.HardwareAddr = linklayer[6:12]
			var iplayer []byte = packet.NetworkLayer().LayerContents()
			var s_ip net.IP = iplayer[12:16]
			var d_ip net.IP = iplayer[16:20]
			var s_port layers.TCPPort = layers.TCPPort(binary.BigEndian.Uint16(tcp.Contents[0:2]))
			var d_port layers.TCPPort = layers.TCPPort(binary.BigEndian.Uint16(tcp.Contents[2:4]))
			var seq = binary.BigEndian.Uint32(tcp.Contents[4:8])
			var ack = binary.BigEndian.Uint32(tcp.Contents[8:12])
			//var content_len uint32 = uint32(len(tcp.LayerContents()))
			if tcp.SYN && !tcp.ACK {
				// fmt.Println("收到客户端发过来的SYN包")
				var buf gopacket.SerializeBuffer = BuildSynAckPacket(d_mac, s_mac, d_ip, s_ip, d_port, s_port, seq*2-1, seq+1)
				err = handle.WritePacketData(buf.Bytes())
				if err != nil {
					fmt.Println("send packet error")
				}
				// fmt.Println("send done.")
			}
			//判断是不是心跳检测，如果是的话返回假的心跳
			if !tcp.SYN && !tcp.FIN && tcp.PSH && tcp.ACK {
				// fmt.Println("发现用于心跳检测(PSH数据)的报文，需要返回确认信息: PSH & ACK",sip,sport,dip,dport)
				var buf gopacket.SerializeBuffer = BuildAckAckPacket(d_mac, s_mac, d_ip, s_ip, d_port, s_port, ack, seq+1)
				err = handle.WritePacketData(buf.Bytes())
				if err != nil {
					fmt.Println("send packet error")
				}
				// fmt.Println("send done.")
			}
			if tcp.SYN && tcp.ACK {
				// fmt.Println("应该是我这边发送的假报文 返回SYN+ACK")
			}
			if !tcp.SYN && tcp.ACK && !tcp.FIN && !tcp.PSH {
				//这里不需要回复
				// fmt.Println("应该是客户端发送的ACK报文，需要一个ACK，确认一下收到包")
				//var buf gopacket.SerializeBuffer = BuildOnlyAckPacket(d_mac, s_mac, d_ip, s_ip, d_port, s_port, ack, seq+1)
				//err = handle.WritePacketData(buf.Bytes())
				//if err != nil {
				//	fmt.Println("send packet error")
				//}
				// fmt.Println("send done.")
			}
			if tcp.FIN && tcp.ACK {
				// fmt.Println("客户端发送了FIN+ACK报文")
				var buf gopacket.SerializeBuffer = BuildFinAckPacket(d_mac, s_mac, d_ip, s_ip, d_port, s_port, ack, seq+1)
				err = handle.WritePacketData(buf.Bytes())
				if err != nil {
					fmt.Println("send packet error")
				}
				// fmt.Println("send done.")
			}
		}
	}
}

// Only ACK
func BuildOnlyAckPacket(sMac net.HardwareAddr, dMac net.HardwareAddr, sIP net.IP, dIP net.IP, sPort layers.TCPPort, dPort layers.TCPPort, synSeq uint32, synAck uint32) gopacket.SerializeBuffer {
	eth := layers.Ethernet{
		SrcMAC:       sMac,
		DstMAC:       dMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    sIP,
		DstIP:    dIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: sPort,
		DstPort: dPort,
		Seq:     synSeq,
		Ack:     synAck,
		Window:  65280,
		ACK:     true,
		FIN:     false,
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

//FIN && ACK
func BuildFinAckPacket(sMac net.HardwareAddr, dMac net.HardwareAddr, sIP net.IP, dIP net.IP, sPort layers.TCPPort, dPort layers.TCPPort, synSeq uint32, synAck uint32) gopacket.SerializeBuffer {
	eth := layers.Ethernet{
		SrcMAC:       sMac,
		DstMAC:       dMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    sIP,
		DstIP:    dIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: sPort,
		DstPort: dPort,
		Seq:     synSeq,
		Ack:     synAck,
		Window:  65280,
		ACK:     true,
		FIN:     true,
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

//PSH && ACK
func BuildAckAckPacket(sMac net.HardwareAddr, dMac net.HardwareAddr, sIP net.IP, dIP net.IP, sPort layers.TCPPort, dPort layers.TCPPort, synSeq uint32, synAck uint32) gopacket.SerializeBuffer {
	eth := layers.Ethernet{
		SrcMAC:       sMac,
		DstMAC:       dMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    sIP,
		DstIP:    dIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: sPort,
		DstPort: dPort,
		Seq:     synSeq,
		Ack:     synAck,
		Window:  65280,
		SYN:     false,
		ACK:     true,
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

// SYN && ACK
func BuildSynAckPacket(sMac net.HardwareAddr, dMac net.HardwareAddr, sIP net.IP, dIP net.IP, sPort layers.TCPPort, dPort layers.TCPPort, synSeq uint32, synAck uint32) gopacket.SerializeBuffer {
	eth := layers.Ethernet{
		SrcMAC:       sMac,
		DstMAC:       dMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    sIP,
		DstIP:    dIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: sPort,
		DstPort: dPort,
		Seq:     synSeq,
		Ack:     synAck,
		Window:  65280,
		SYN:     true,
		ACK:     true,
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
