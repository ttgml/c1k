package server

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

//这个方法主要用来抓取数据包，以及模拟建立连接和端开连接(SYN+FIN)
func HanderPacket(deviceName string, host string, port string) {
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	handle.SetBPFFilter("port " + port + " and dst host " + host)
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
			var dmac []byte = linklayer[0:6]
			var smac []byte = linklayer[6:12]
			// fmt.Println(smac,dmac)
			var iplayer []byte = packet.NetworkLayer().LayerContents()
			var sip []byte = iplayer[12:16]
			var dip []byte = iplayer[16:20]
			// fmt.Println(sip,dip)
			var sport = tcp.Contents[0:2]
			var dport = tcp.Contents[2:4]
			var synSeq = tcp.Contents[4:8]
			var synAck = tcp.Contents[8:12]
			// fmt.Println(sport,dport)

			if tcp.SYN && !tcp.ACK {
				// fmt.Println("收到客户端发过来的SYN包")
				var buf gopacket.SerializeBuffer = BuildSynAckPacket(smac, dmac, sip, dip, sport, dport, synSeq, synAck)
				err = handle.WritePacketData(buf.Bytes())
				if err != nil {
					fmt.Println("send packet error")
				}
				// fmt.Println("send done.")
			}
			//判断是不是心跳检测，如果是的话返回假的心跳
			if !tcp.SYN && !tcp.FIN && tcp.PSH && tcp.ACK {
				// fmt.Println("发现用于心跳检测(PSH数据)的报文，需要返回确认信息: PSH & ACK",sip,sport,dip,dport)
				var buf gopacket.SerializeBuffer = BuildAckAckPacket(smac, dmac, sip, dip, sport, dport, synSeq, synAck)
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
				// fmt.Println("应该是客户端发送的ACK报文，需要一个ACK，确认一下收到包")
				var buf gopacket.SerializeBuffer = BuildOnlyAckPacket(smac, dmac, sip, dip, sport, dport, synSeq, synAck)
				err = handle.WritePacketData(buf.Bytes())
				if err != nil {
					fmt.Println("send packet error")
				}
				// fmt.Println("send done.")
			}
			if tcp.FIN && tcp.ACK {
				// fmt.Println("客户端发送了FIN+ACK报文")
				var buf gopacket.SerializeBuffer = BuildFinAckPacket(smac, dmac, sip, dip, sport, dport, synSeq, synAck)
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
func BuildOnlyAckPacket(sMac []byte, dMac []byte, sIP []byte, dIP []byte, sPort []byte, dPort []byte, synSeq []byte, synAck []byte) gopacket.SerializeBuffer {
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
func BuildFinAckPacket(sMac []byte, dMac []byte, sIP []byte, dIP []byte, sPort []byte, dPort []byte, synSeq []byte, synAck []byte) gopacket.SerializeBuffer {
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
func BuildAckAckPacket(sMac []byte, dMac []byte, sIP []byte, dIP []byte, sPort []byte, dPort []byte, synSeq []byte, synAck []byte) gopacket.SerializeBuffer {
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
		Seq:     binary.BigEndian.Uint32(synAck) + 1,
		Ack:     binary.BigEndian.Uint32(synSeq) + 1,
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
func BuildSynAckPacket(sMac []byte, dMac []byte, sIP []byte, dIP []byte, sPort []byte, dPort []byte, synSeq []byte, synAck []byte) gopacket.SerializeBuffer {
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
		Seq:     binary.BigEndian.Uint32(synSeq) - 1,
		Ack:     binary.BigEndian.Uint32(synSeq) + 1,
		Window:  65280,
		SYN:     true,
		ACK:     true,
	}
	//data := []byte(`abc`)
	//payload := gopacket.Payload(data)
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
