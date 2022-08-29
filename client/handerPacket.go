package client

import (
	"encoding/binary"
	"fmt"
	"io"

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
			var dmac []byte = linklayer[0:6]
			var smac []byte = linklayer[6:12]
			//fmt.Println(smac,dmac)
			var iplayer []byte = packet.NetworkLayer().LayerContents()
			var sip []byte = iplayer[12:16]
			var dip []byte = iplayer[16:20]
			//fmt.Println(sip,dip)
			var sport = tcp.Contents[0:2]
			var dport = tcp.Contents[2:4]
			var synSeq = tcp.Contents[4:8]
			var synAck = tcp.Contents[8:12]
			//fmt.Println(sport,dport)
			if tcp.SYN && tcp.ACK {
				// fmt.Println("SYN+ACK 第二次挥手", dip,sip)
				buf := BuildSynAckAckPacket(smac, dmac, sip, dip, dport, sport, synSeq, synAck)
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
func BuildSynAckAckPacket(sMac []byte, dMac []byte, sIP []byte, dIP []byte, dPort []byte, sPort []byte, synSeq []byte, synAck []byte) gopacket.SerializeBuffer {
	eth := layers.Ethernet{
		SrcMAC:       dMac,
		DstMAC:       sMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    dIP,
		DstIP:    sIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(binary.BigEndian.Uint16(dPort)),
		DstPort: layers.TCPPort(binary.BigEndian.Uint16(sPort)),
		Seq:     binary.BigEndian.Uint32(synAck),
		Ack:     binary.BigEndian.Uint32(synSeq) + 1,
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
