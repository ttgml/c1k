package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

//这个方法主要用来抓取服务端返回的数据包，并且返回第三次握手包
func HanderPacket(deviceName string, port int) {
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	handle.SetBPFFilter("src port " + string(port))
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
			//fmt.Println("SYN: ",tcp.SYN,tcp.ACK,tcp.PSH,tcp.FIN)
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
			if tcp.SYN && tcp.ACK {
				// fmt.Println("SYN+ACK 第二次挥手", dip,sip)
				buf := BuildSynAckAckPacket(d_mac, s_mac, d_ip, s_ip, s_port, d_port, ack, seq+1)
				err = handle.WritePacketData(buf.Bytes())
				if err != nil {
					fmt.Println("send packet error")
				}
				// fmt.Println("send done.")
			}
		}
	}
}

//构建第三次握手包
func BuildSynAckAckPacket(sMac net.HardwareAddr, dMac net.HardwareAddr, sIP net.IP, dIP net.IP, dPort layers.TCPPort, sPort layers.TCPPort, synSeq uint32, synAck uint32) gopacket.SerializeBuffer {
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
		Window:  502,
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
