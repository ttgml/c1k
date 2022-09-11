package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

//这个方法主要用来抓取服务端返回的数据包，并且返回第三次握手包
func HanderPacket(wg *sync.WaitGroup) {
	handle, err := pcap.OpenLive(C_interface, 1600, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}
	handle.SetBPFFilter("tcp src port " + strconv.Itoa(int(C_port)) + "and src host " + C_host)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//等准备好抓包之后，通知默认goroutine继续执行后面的代码
	wg.Done()
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
			var payload_len uint32 = uint32(len(tcp.Payload))

			// TODO 这里总是会收到一些不相关的包，需要做一下过滤
			// 统计的时候会出现问题
			if tcp.SYN && tcp.ACK {
				// fmt.Println("SYN+ACK 第二次挥手", dip,sip)
				fmt.Println(s_ip,d_ip)
				buf := BuildSynAckAckPacket(d_mac, s_mac, d_ip, s_ip, s_port, d_port, ack, seq+1)
				err = handle.WritePacketData(buf.Bytes())
				if err != nil {
					fmt.Println("send packet error")
				}
				est_count++
				if C_keepalive {
					//这里判断如果服务端回了SYN的确认包，要记录目标（也就是客户端的IP和端口），在后面发送psh的时候要用到
					//还有seq和ack ，后期可能会增加 len 的长度
					pk := PshKey{
						Ip:   d_ip.String(),
						Port: uint16(d_port),
					}
					pv := PshValue{
						Ack: seq + payload_len,
						Seq: ack,
					}
					mapPshListSync.Store(pk, pv)
				}
			}
			if tcp.ACK && !tcp.SYN && !tcp.FIN && !tcp.RST && !tcp.PSH {
				//PSH包之后，服务端会返回一个ACK，这里要记录这个这个返回的Ack和Seq，下一次PSH会用到。
				//这里不需要回包
				//TODO 这里可能需要判断一下是否是服务端发送过来的ACK，之要处理客户端发送过来的ACK
				if C_port != s_port {
					break
				}
				if C_keepalive {
					pk := PshKey{
						Ip:   d_ip.String(),
						Port: uint16(d_port),
					}
					pv := PshValue{
						Ack: seq + payload_len,
						Seq: ack,
					}
					mapPshListSync.Store(pk, pv)
				}
			}

			if tcp.RST && !tcp.ACK {
				if C_keepalive {
					pk := PshKey{
						Ip:   s_ip.String(),
						Port: uint16(s_port),
					}
					mapPshListSync.Delete(pk)
				}

				rst_count++
			}
			if tcp.RST && tcp.ACK {
				if C_keepalive {
					pk := PshKey{
						Ip:   s_ip.String(),
						Port: uint16(s_port),
					}
					mapPshListSync.Delete(pk)
				}
				//这属于 服务器拒绝了 连接（因为服务端没有监听对应的端口，所以返回了RST+ACK）
				rst_count++
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
